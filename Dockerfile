FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install
COPY requirements_standalone.txt .
RUN pip install --no-cache-dir -r requirements_standalone.txt

# Copy app code
COPY . .

# Expose port
EXPOSE 9011

# Run
CMD ["python", "app.py"]
