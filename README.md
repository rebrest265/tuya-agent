# Tuya Environmental Collector Agent

The Tuya Environmental Collector Agent is a cloud-native service designed to poll temperature and humidity metrics from Tuya-compatible sensors and publish them to InfluxDB. It features a web-based configuration panel and uses SQLite for local configuration persistence.

## Features

- **Pure API Client**: Communicates directly with the Tuya Cloud OpenAPI using standard HTTP requests and signature calculations, eliminating the need for the Tuya SDK.
- **Dynamic Device Support**: Automatically parses metrics based on the device product name. It natively supports devices identifying as `T & H Sensor` and `Temperature & Humidity Sensor` out of the box.
- **SQLite Persistence**: Stores connection settings and registered devices in a local database file, allowing configurations to persist across service restarts.
- **On-Demand Synchronization**: Automatically updates all registered sensors every hour, with support for manual synchronization via the Web UI.
- **Web Configurator UI**: A clean, system-neutral configuration dashboard with three tabs:
  - **Devices**: Register, inspect, and delete sensor nodes.
  - **Settings**: Adjust Tuya API keys, InfluxDB endpoint credentials, and logger verbosity levels.
  - **Diagnostics & Help**: Readme guide and a real-time console streaming container logs on demand.
- **Multi-Architecture Support**: Building image for amd64 and aarch64 with Github Actions

## Parsing Specification

The agent differentiates data decoding formats based on the `product_name` field of the sensor:
- **Devices identifying as "T & H Sensor"**: Decodes `temp_current` (divided by 10), `humidity_value` (percentage), and `battery_state` (string values like "middle").
- **Devices identifying as "Temperature & Humidity Sensor"**: Decodes `va_temperature` (divided by 10), `va_humidity` (percentage), and `battery_percentage` (integer percentages).
- **Fallback**: Dynamically attempts to read any of the status codes above if the sensor's product name does not match either specific naming scheme.

## Setup and Local Execution

### Prerequisites
- Python 3.10 or higher
- InfluxDB instance (v2.x)
- Tuya Cloud Developer account with access credentials

### Installation
1. Clone the repository and navigate to the project root directory.
2. Install the python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Set the environment variable for the database destination (defaults to `/data/agent.db`):
   ```bash
   # On Windows (PowerShell)
   $env:DB_PATH="agent.db"
   
   # On Linux/macOS
   export DB_PATH="agent.db"
   ```
4. Start the application:
   ```bash
   python app.py
   ```
5. Open a web browser and navigate to `http://localhost:5000` to access the configurator dashboard.

## Containerization

The repository includes a `Dockerfile` so you can build your own image to run it in Docker. The latest builds are automatically generated and published via GitHub Actions workflows.

To build the image locally:
```bash
docker build --build-arg VERSION=v1.0.0 -t tuya-agent:v1.0.0 .
```

To build a multi-architecture image (e.g., for `linux/amd64` and `linux/arm64`) and push to a remote registry:
```bash
docker buildx build --platform linux/amd64,linux/arm64 --build-arg VERSION=v1.0.0 -t your-registry/tuya-agent:v1.0.0 --push .
```

## Kubernetes Deployment

An example deployment configuration is provided in `example-deployment.yaml`. It sets up:
- A `PersistentVolume` using a local host path (`/mnt/tuya-agent-data`).
- A `PersistentVolumeClaim` to mount the storage to `/data` in the container.
- A `Deployment` with a single replica (using `Recreate` rollout strategy to allow SQLite access).
- A `Service` of type `NodePort` mapping traffic from port `30845` to port `5000` of the application.

Deploy the manifest to a cluster using:
```bash
kubectl apply -f example-deployment.yaml
```
