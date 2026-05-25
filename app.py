import os
import time
import hashlib
import hmac
import logging
import sqlite3
import threading
from collections import deque
from urllib.parse import urlencode

import requests
from flask import Flask, jsonify, request, render_template
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

# -------------------------------------------------------------
# Configuration & Constants
# -------------------------------------------------------------
DB_PATH = os.environ.get("DB_PATH", "/data/agent.db")
BUILD_VERSION = os.environ.get("BUILD_VERSION", "dev")

# Ensure the database directory exists
_db_dir = os.path.dirname(os.path.abspath(DB_PATH))
os.makedirs(_db_dir, exist_ok=True)

# -------------------------------------------------------------
# Logging Configuration
# -------------------------------------------------------------
logger = logging.getLogger("tuya_agent")
logger.setLevel(logging.INFO)

class DequeHandler(logging.Handler):
    def __init__(self, maxlen=500):
        super().__init__()
        self.logs = deque(maxlen=maxlen)

    def emit(self, record):
        try:
            self.logs.append(self.format(record))
        except Exception:
            pass

deque_handler = DequeHandler()
deque_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(deque_handler)

console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(console_handler)

# -------------------------------------------------------------
# Database Setup
# -------------------------------------------------------------
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db_is_new = not os.path.exists(DB_PATH)
    logger.info(f"Initializing database at: {DB_PATH} ({'creating new' if db_is_new else 'opening existing'})")
    conn = get_db_connection()
    try:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            tuya_url TEXT,
            tuya_client_id TEXT,
            tuya_client_secret TEXT,
            influx_url TEXT,
            influx_token TEXT,
            influx_org TEXT,
            influx_bucket TEXT,
            log_level TEXT DEFAULT 'INFO'
        )
        """)
        logger.debug("Table 'settings' verified.")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            location TEXT NOT NULL,
            name TEXT,
            product_name TEXT,
            online INTEGER,
            temperature REAL,
            humidity REAL,
            battery TEXT,
            last_seen TEXT,
            last_error TEXT
        )
        """)
        logger.debug("Table 'devices' verified.")
        # Always ensure the single settings row exists (initial DB seed)
        result = conn.execute("""
        INSERT OR IGNORE INTO settings (id, tuya_url, tuya_client_id, tuya_client_secret, influx_url, influx_token, influx_org, influx_bucket, log_level)
        VALUES (1, 'https://openapi.tuyaeu.com', '', '', '', '', '', '', 'INFO')
        """)
        if result.rowcount > 0:
            logger.info("Initial settings row seeded into database.")
        conn.commit()
        logger.info("Database initialization complete.")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise
    finally:
        conn.close()

def apply_log_level_from_db():
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT log_level FROM settings WHERE id = 1").fetchone()
        if row:
            level_name = row["log_level"]
            level = getattr(logging, level_name.upper(), logging.INFO)
            logger.setLevel(level)
            # Apply to root logger as well
            logging.getLogger().setLevel(level)
            logger.info(f"Log level set to {level_name}")
    except Exception as e:
        logger.error(f"Error applying log level: {e}")
    finally:
        conn.close()

# -------------------------------------------------------------
# Tuya Client (Pure API)
# -------------------------------------------------------------
class TuyaClient:
    def __init__(self, url, client_id, secret):
        self.url = url.rstrip('/')
        self.client_id = client_id
        self.secret = secret
        # Thread-safe token caching
        self._lock = threading.Lock()
        self.access_token = None
        self.token_expires_at = 0

    def _get_headers(self, path, query_params=None, body="", access_token=None):
        t = str(int(time.time() * 1000))
        method = "GET"
        body_sha256 = hashlib.sha256(body.encode("utf-8")).hexdigest()
        
        if query_params:
            query_str = urlencode(sorted(query_params.items()))
            url_path_with_query = f"{path}?{query_str}"
        else:
            url_path_with_query = path
            
        sign_string = f"{method}\n{body_sha256}\n\n{url_path_with_query}"
        
        if access_token:
            sign_payload = self.client_id + access_token + t + sign_string
        else:
            sign_payload = self.client_id + t + sign_string
            
        sign = hmac.new(
            self.secret.encode("utf-8"),
            msg=sign_payload.encode("utf-8"),
            digestmod=hashlib.sha256
        ).hexdigest().upper()
        
        headers = {
            "client_id": self.client_id,
            "sign": sign,
            "t": t,
            "sign_method": "HMAC-SHA256",
            "Content-Type": "application/json"
        }
        if access_token:
            headers["access_token"] = access_token
            
        return headers

    def get_token(self):
        with self._lock:
            now = time.time()
            if self.access_token and now < self.token_expires_at - 300:
                remaining = int(self.token_expires_at - now)
                logger.debug(f"Using cached Tuya access token (expires in ~{remaining}s).")
                return self.access_token

            logger.info("Cached token absent or near expiry. Fetching fresh access token from Tuya...")
            query = {"grant_type": "1"}
            path = "/v1.0/token"
            headers = self._get_headers(path, query_params=query)
            
            try:
                resp = requests.get(f"{self.url}{path}?grant_type=1", headers=headers, timeout=10)
                resp.raise_for_status()
                data = resp.json()
                if data.get("success"):
                    self.access_token = data["result"]["access_token"]
                    expires_in = data["result"].get("expire_time", 7200)
                    self.token_expires_at = now + expires_in
                    logger.info("Successfully fetched new Tuya access token.")
                    return self.access_token
                else:
                    raise Exception(data.get("msg", "Unknown error"))
            except Exception as e:
                logger.error(f"Failed to fetch Tuya token: {e}")
                return None

    def get_device(self, device_id):
        token = self.get_token()
        if not token:
            raise Exception("Cannot fetch device info: Failed to retrieve access token")

        path = f"/v1.0/devices/{device_id}"
        headers = self._get_headers(path, access_token=token)
        
        try:
            resp = requests.get(f"{self.url}{path}", headers=headers, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            if data.get("success"):
                return data["result"]
            else:
                raise Exception(data.get("msg", "Unknown error"))
        except Exception as e:
            logger.error(f"Failed to fetch device details for ID {device_id}: {e}")
            raise e

# -------------------------------------------------------------
# Parser Logic
# -------------------------------------------------------------
def parse_status(product_name, status_list):
    product_name_lower = (product_name or "").lower()
    temp = None
    hum = None
    battery = None
    
    # Check by product name first
    is_type2 = "temperature & humidity sensor" in product_name_lower
    is_type1 = "t & h sensor" in product_name_lower
    
    if is_type2:
        temp_val = next((x["value"] for x in status_list if x.get("code") == "va_temperature"), None)
        hum_val = next((x["value"] for x in status_list if x.get("code") == "va_humidity"), None)
        bat_val = next((x["value"] for x in status_list if x.get("code") == "battery_percentage"), None)
    elif is_type1:
        temp_val = next((x["value"] for x in status_list if x.get("code") == "temp_current"), None)
        hum_val = next((x["value"] for x in status_list if x.get("code") == "humidity_value"), None)
        bat_val = next((x["value"] for x in status_list if x.get("code") == "battery_state"), None)
    else:
        # Fallback/dynamic detection
        temp_val = next((x["value"] for x in status_list if x.get("code") in ("va_temperature", "temp_current")), None)
        hum_val = next((x["value"] for x in status_list if x.get("code") in ("va_humidity", "humidity_value")), None)
        bat_val = next((x["value"] for x in status_list if x.get("code") in ("battery_percentage", "battery_state")), None)

    if temp_val is not None:
        try:
            # Temperature is reported in tenths of a degree (e.g. 184 -> 18.4)
            temp = float(temp_val) / 10.0
        except (ValueError, TypeError):
            pass
    if hum_val is not None:
        try:
            hum = float(hum_val)
        except (ValueError, TypeError):
            pass
            
    battery = bat_val
    return temp, hum, battery

# -------------------------------------------------------------
# InfluxDB Writer
# -------------------------------------------------------------
def write_to_influx(settings, device_id, device_name, product_name, location, online, temp, hum, battery):
    url = settings["influx_url"]
    token = settings["influx_token"]
    org = settings["influx_org"]
    bucket = settings["influx_bucket"]
    
    if not all([url, token, org, bucket]):
        logger.warning(f"InfluxDB settings are incomplete. Skipping metric write for {device_id}.")
        return
        
    try:
        with InfluxDBClient(url=url, token=token, org=org, timeout=10000) as client:
            write_api = client.write_api(write_options=SYNCHRONOUS)
            
            point = Point("tuya_sensor") \
                .tag("device_id", device_id) \
                .tag("device_name", device_name or "Unknown") \
                .tag("product_name", product_name or "Unknown") \
                .tag("location", location) \
                .field("online", bool(online))
                
            if temp is not None:
                point = point.field("temperature", float(temp))
            if hum is not None:
                point = point.field("humidity", float(hum))
            if battery is not None:
                if isinstance(battery, (int, float)):
                    point = point.field("battery_percentage", float(battery))
                else:
                    point = point.field("battery_state", str(battery))
                    
            write_api.write(bucket=bucket, org=org, record=point)
            logger.info(f"Successfully published metrics for device {device_id} to InfluxDB.")
    except Exception as e:
        logger.error(f"Failed to publish metrics to InfluxDB for device {device_id}: {e}")
        raise e

# -------------------------------------------------------------
# Core Engine - Collection Logic
# -------------------------------------------------------------
db_lock = threading.Lock()

def run_collection(device_id=None):
    logger.info("Executing collection task...")
    with db_lock:
        conn = get_db_connection()
        try:
            settings = conn.execute("SELECT * FROM settings WHERE id = 1").fetchone()
            if not settings:
                logger.error("Database settings record not found. Aborting collection.")
                return

            if not settings["tuya_client_id"] or not settings["tuya_client_secret"]:
                logger.warning("Tuya Client ID or Secret is not configured. Skipping collection task.")
                return

            if device_id:
                devices = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchall()
            else:
                devices = conn.execute("SELECT * FROM devices").fetchall()

            if not devices:
                logger.info("No devices registered in database. Collection skipped.")
                return

            # Instantiate client
            tuya_client = TuyaClient(
                url=settings["tuya_url"],
                client_id=settings["tuya_client_id"],
                secret=settings["tuya_client_secret"]
            )

            for dev in devices:
                dev_id = dev["id"]
                location = dev["location"]
                logger.info(f"Querying device: {dev_id} ({location})")
                
                try:
                    data = tuya_client.get_device(dev_id)
                    name = data.get("name", dev["name"])
                    product_name = data.get("product_name", dev["product_name"])
                    online = 1 if data.get("online", True) else 0
                    status_list = data.get("status", [])
                    
                    temp, hum, battery = parse_status(product_name, status_list)
                    last_seen = time.strftime('%Y-%m-%d %H:%M:%S')
                    
                    # Update local cache in DB
                    conn.execute("""
                        UPDATE devices
                        SET name = ?, product_name = ?, online = ?, temperature = ?, humidity = ?, battery = ?, last_seen = ?, last_error = NULL
                        WHERE id = ?
                    """, (name, product_name, online, temp, hum, battery, last_seen, dev_id))
                    conn.commit()
                    
                    # Write to InfluxDB
                    write_to_influx(settings, dev_id, name, product_name, location, online, temp, hum, battery)
                    
                except Exception as e:
                    err_msg = str(e)
                    logger.error(f"Error querying device {dev_id}: {err_msg}")
                    conn.execute("""
                        UPDATE devices
                        SET last_error = ?, online = 0
                        WHERE id = ?
                    """, (err_msg, dev_id))
                    conn.commit()
        finally:
            conn.close()

# -------------------------------------------------------------
# Background Scheduler
# -------------------------------------------------------------
shutdown_event = threading.Event()

COLLECTION_INTERVAL_SECONDS = int(os.environ.get("COLLECTION_INTERVAL", "3600"))

def scheduler_worker():
    logger.info("Background scheduler thread initialized.")
    logger.info(f"Collection interval: {COLLECTION_INTERVAL_SECONDS}s. Running initial sync in 5s...")
    time.sleep(5)

    while not shutdown_event.is_set():
        try:
            run_collection()
        except Exception as e:
            logger.error(f"Unhandled error in scheduler execution cycle: {e}")

        logger.info(f"Next collection scheduled in {COLLECTION_INTERVAL_SECONDS}s.")
        # Poll shutdown event in short intervals to allow clean exit
        for _ in range(COLLECTION_INTERVAL_SECONDS):
            if shutdown_event.is_set():
                logger.info("Shutdown signal received. Exiting scheduler.")
                break
            time.sleep(1)

# -------------------------------------------------------------
# Flask Web App Setup & Endpoints
# -------------------------------------------------------------
app = Flask(__name__)

# Bootstrap: run regardless of whether app is started via __main__ or
# imported by a WSGI server (Gunicorn). This ensures the DB tables always
# exist before any request is handled, and the collection worker is running.
logger.info("=" * 60)
logger.info(" Tuya Agent initializing")
logger.info(f" Version  : {BUILD_VERSION}")
logger.info(f" Database : {DB_PATH}")
logger.info("=" * 60)
init_db()
apply_log_level_from_db()
_scheduler_thread = threading.Thread(target=scheduler_worker, daemon=True, name="scheduler")
_scheduler_thread.start()
logger.info("Background scheduler thread started.")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/info")
def get_info():
    return jsonify({
        "version": BUILD_VERSION,
        "database": DB_PATH
    })

@app.route("/api/settings", methods=["GET"])
def get_settings():
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM settings WHERE id = 1").fetchone()
        return jsonify(dict(row) if row else {})
    finally:
        conn.close()

@app.route("/api/settings", methods=["POST"])
def update_settings():
    data = request.json or {}
    conn = get_db_connection()
    try:
        conn.execute("""
            UPDATE settings
            SET tuya_url = ?,
                tuya_client_id = ?,
                tuya_client_secret = ?,
                influx_url = ?,
                influx_token = ?,
                influx_org = ?,
                influx_bucket = ?,
                log_level = ?
            WHERE id = 1
        """, (
            data.get("tuya_url", "https://openapi.tuyaeu.com"),
            data.get("tuya_client_id", ""),
            data.get("tuya_client_secret", ""),
            data.get("influx_url", ""),
            data.get("influx_token", ""),
            data.get("influx_org", ""),
            data.get("influx_bucket", ""),
            data.get("log_level", "INFO")
        ))
        conn.commit()
    finally:
        conn.close()
        
    # Dynamically apply updated logger setting
    apply_log_level_from_db()
    return jsonify({"success": True, "message": "Settings saved successfully"})

@app.route("/api/devices", methods=["GET"])
def get_devices():
    conn = get_db_connection()
    try:
        rows = conn.execute("SELECT * FROM devices").fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()

@app.route("/api/devices", methods=["POST"])
def add_device():
    data = request.json or {}
    dev_id = data.get("id", "").strip()
    location = data.get("location", "").strip()

    if not dev_id or not location:
        return jsonify({"success": False, "message": "Device ID and Location are required"}), 400

    conn = get_db_connection()
    try:
        # Check duplicate
        exists = conn.execute("SELECT 1 FROM devices WHERE id = ?", (dev_id,)).fetchone()
        if exists:
            return jsonify({"success": False, "message": f"Device {dev_id} is already registered"}), 400

        conn.execute("INSERT INTO devices (id, location, online) VALUES (?, ?, 0)", (dev_id, location))
        conn.commit()
    finally:
        conn.close()

    # Trigger async/immediate poll for the newly added device
    logger.info(f"Registered new device: {dev_id}. Triggering initial pull.")
    threading.Thread(target=run_collection, args=(dev_id,)).start()
    
    return jsonify({"success": True, "message": "Device registered. Initiating connection..."})

@app.route("/api/devices/<device_id>", methods=["DELETE"])
def delete_device(device_id):
    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
        conn.commit()
        return jsonify({"success": True, "message": "Device deleted successfully"})
    finally:
        conn.close()

@app.route("/api/devices/sync", methods=["POST"])
def force_sync():
    # Run sync for all devices asynchronously
    threading.Thread(target=run_collection).start()
    return jsonify({"success": True, "message": "Global collection sync scheduled"})

@app.route("/api/logs", methods=["GET"])
def get_logs():
    return jsonify({
        "logs": list(deque_handler.logs)
    })

# -------------------------------------------------------------
# Main Entry Point (local dev only — Gunicorn skips this)
# -------------------------------------------------------------
def main():
    # DB init and scheduler already started at module load above.
    # This block only runs when executing: python app.py
    try:
        logger.info("Starting Flask development server on 0.0.0.0:5000")
        app.run(host="0.0.0.0", port=5000)
    finally:
        logger.info("Shutdown signal received. Stopping scheduler...")
        shutdown_event.set()

if __name__ == "__main__":
    main()
