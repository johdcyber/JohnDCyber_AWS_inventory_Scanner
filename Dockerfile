# Dockerfile

FROM python:3.11-slim

# Install system dependencies if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for security
RUN useradd -m appuser

WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project
COPY . /app/

# Adjust ownership to the non-root user
RUN chown -R appuser:appuser /app
USER appuser

# By default, run the main script
CMD ["python", "-m", "inventory.main"]
