FROM python:3.11-slim

# Prevent Python from writing pyc files to disc and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DB_PATH="/data/agent.db"

# Define version build argument (injected by CI via --build-arg BUILD_VERSION=<tag>)
ARG BUILD_VERSION=dev
ENV BUILD_VERSION=${BUILD_VERSION}

WORKDIR /app

# Copy dependency list and install them
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code files
COPY templates/ templates/
COPY app.py .

# Create folder for SQLite data persistence
RUN mkdir -p /data
VOLUME /data

# Expose Web Portal
EXPOSE 5000

# Run Flask application using production-ready Gunicorn WSGI server
CMD ["gunicorn", "--workers", "1", "--threads", "4", "--bind", "0.0.0.0:5000", "app:app"]
