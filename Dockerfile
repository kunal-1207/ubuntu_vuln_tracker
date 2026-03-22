# Use a slim Ubuntu base image
FROM ubuntu:22.04

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

# Install Python and necessary tools
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    dpkg-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create data directory for cache
RUN mkdir -p data

# Default command
ENTRYPOINT ["python3", "cli.py"]
