# The Force Security ASM - Backend Dockerfile
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Set work directory
WORKDIR /app

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    wget \
    git \
    unzip \
    # Nmap for service detection
    nmap \
    # Masscan dependencies
    libpcap-dev \
    # General utilities
    dnsutils \
    # EyeWitness / Chromium dependencies (compatible with Debian trixie)
    chromium \
    xvfb \
    libnss3 \
    libxss1 \
    libasound2t64 \
    fonts-liberation \
    xdg-utils \
    python3-venv \
    libgbm1 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    && rm -rf /var/lib/apt/lists/*

# Install Masscan from source (for latest features)
RUN git clone https://github.com/robertdavidgraham/masscan.git /tmp/masscan \
    && cd /tmp/masscan \
    && make \
    && cp bin/masscan /usr/local/bin/ \
    && rm -rf /tmp/masscan

# Install Go 1.21 for ProjectDiscovery tools
RUN wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz \
    && rm go1.21.5.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV GOPATH="/root/go"

# Install ProjectDiscovery tools and other security utilities
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    && go install -v github.com/projectdiscovery/katana/cmd/katana@latest \
    # waybackurls - Fetch historical URLs from Wayback Machine
    && go install -v github.com/tomnomnom/waybackurls@latest

# Update nuclei templates
RUN nuclei -update-templates || true

# Install EyeWitness
RUN git clone https://github.com/RedSiege/EyeWitness.git /opt/EyeWitness \
    && cd /opt/EyeWitness \
    && python3 -m venv eyewitness-venv \
    && ./eyewitness-venv/bin/pip install --upgrade pip \
    && ./eyewitness-venv/bin/pip install selenium netaddr rapidfuzz \
    && chmod +x Python/EyeWitness.py

# Set EyeWitness environment variables
ENV EYEWITNESS_PATH="/opt/EyeWitness/Python/EyeWitness.py"
ENV EYEWITNESS_VENV="/opt/EyeWitness/eyewitness-venv/bin/python"
ENV SCREENSHOTS_DIR="/app/data/screenshots"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user for security
RUN adduser --disabled-password --gecos '' appuser \
    && chown -R appuser:appuser /app \
    && mkdir -p /home/appuser/.config/nuclei \
    && cp -r /root/.config/nuclei/* /home/appuser/.config/nuclei/ 2>/dev/null || true \
    && chown -R appuser:appuser /home/appuser \
    && mkdir -p /app/data/screenshots \
    && chown -R appuser:appuser /app/data \
    && chown -R appuser:appuser /opt/EyeWitness

# Copy Go binaries for appuser
RUN mkdir -p /home/appuser/go/bin \
    && cp /root/go/bin/* /home/appuser/go/bin/ \
    && chown -R appuser:appuser /home/appuser/go

# Note: Some scanning tools (masscan, naabu SYN scan) require root privileges
# For production, run specific scan containers with appropriate capabilities

USER appuser
ENV PATH="/home/appuser/go/bin:/usr/local/bin:${PATH}"

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
