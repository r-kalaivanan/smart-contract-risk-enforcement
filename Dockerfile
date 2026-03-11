# SC-Guard Docker Image
# Multi-stage build for optimized image size

# Stage 1: Builder
FROM python:3.10-slim as builder

# Install system dependencies required for building
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Runtime
FROM python:3.10-slim

# Install Solidity compiler and runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    solc \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 scguard && \
    mkdir -p /app /data && \
    chown -R scguard:scguard /app /data

# Set working directory
WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /root/.local /home/scguard/.local

# Copy application code
COPY --chown=scguard:scguard . .

# Switch to non-root user
USER scguard

# Add local packages to PATH
ENV PATH=/home/scguard/.local/bin:$PATH
ENV PYTHONPATH=/app:$PYTHONPATH

# Install sc-guard in development mode
RUN pip install --user -e .

# Expose API port (for future API module)
EXPOSE 8000

# Volume for contract files and models
VOLUME ["/data"]

# Default command: show help
CMD ["sc-guard", "--help"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Labels for metadata
LABEL maintainer="sc-guard developers"
LABEL description="Smart Contract Vulnerability Detection System"
LABEL version="0.1.0"
