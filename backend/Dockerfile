# syntax=docker/dockerfile:1.4
# The Force Security ASM - Backend Dockerfile (Optimized)
# Uses pre-built binaries instead of compiling for faster builds

FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# ============================================
# Stage 1: Download pre-built binaries (FAST)
# ============================================
FROM base AS tool-downloader

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget unzip git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tools

# Detect architecture and download appropriate binaries
ARG TARGETARCH=amd64

# ProjectDiscovery tools - download pre-built binaries (much faster than compiling)
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then PD_ARCH="arm64"; else PD_ARCH="amd64"; fi && \
    # Nuclei
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_${PD_ARCH}.zip" && \
    unzip -o -q "nuclei_3.3.7_linux_${PD_ARCH}.zip" -d /tools && \
    rm "nuclei_3.3.7_linux_${PD_ARCH}.zip" && \
    # Subfinder
    wget -q "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_${PD_ARCH}.zip" && \
    unzip -o -q "subfinder_2.6.7_linux_${PD_ARCH}.zip" -d /tools && \
    rm "subfinder_2.6.7_linux_${PD_ARCH}.zip" && \
    # HTTPX
    wget -q "https://github.com/projectdiscovery/httpx/releases/download/v1.6.10/httpx_1.6.10_linux_${PD_ARCH}.zip" && \
    unzip -o -q "httpx_1.6.10_linux_${PD_ARCH}.zip" -d /tools && \
    rm "httpx_1.6.10_linux_${PD_ARCH}.zip" && \
    # DNSX
    wget -q "https://github.com/projectdiscovery/dnsx/releases/download/v1.2.1/dnsx_1.2.1_linux_${PD_ARCH}.zip" && \
    unzip -o -q "dnsx_1.2.1_linux_${PD_ARCH}.zip" -d /tools && \
    rm "dnsx_1.2.1_linux_${PD_ARCH}.zip" && \
    # Naabu
    wget -q "https://github.com/projectdiscovery/naabu/releases/download/v2.3.3/naabu_2.3.3_linux_${PD_ARCH}.zip" && \
    unzip -o -q "naabu_2.3.3_linux_${PD_ARCH}.zip" -d /tools && \
    rm "naabu_2.3.3_linux_${PD_ARCH}.zip" && \
    # Katana
    wget -q "https://github.com/projectdiscovery/katana/releases/download/v1.1.0/katana_1.1.0_linux_${PD_ARCH}.zip" && \
    unzip -o -q "katana_1.1.0_linux_${PD_ARCH}.zip" -d /tools && \
    rm "katana_1.1.0_linux_${PD_ARCH}.zip" && \
    # Chaos
    wget -q "https://github.com/projectdiscovery/chaos-client/releases/download/v0.5.2/chaos-client_0.5.2_linux_${PD_ARCH}.zip" && \
    unzip -o -q "chaos-client_0.5.2_linux_${PD_ARCH}.zip" -d /tools && \
    rm "chaos-client_0.5.2_linux_${PD_ARCH}.zip" && \
    # TLSX
    wget -q "https://github.com/projectdiscovery/tlsx/releases/download/v1.1.7/tlsx_1.1.7_linux_${PD_ARCH}.zip" && \
    unzip -o -q "tlsx_1.1.7_linux_${PD_ARCH}.zip" -d /tools && \
    rm "tlsx_1.1.7_linux_${PD_ARCH}.zip"

# Other Go tools (pre-built releases)
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then ARCH_SUFFIX="arm64"; else ARCH_SUFFIX="amd64"; fi && \
    # ffuf
    wget -q "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_${ARCH_SUFFIX}.tar.gz" && \
    tar -xzf "ffuf_2.1.0_linux_${ARCH_SUFFIX}.tar.gz" -C /tools && \
    rm "ffuf_2.1.0_linux_${ARCH_SUFFIX}.tar.gz" && \
    # Amass
    wget -q "https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_${ARCH_SUFFIX}.zip" && \
    unzip -o -q "amass_Linux_${ARCH_SUFFIX}.zip" -d /tmp/amass && \
    cp /tmp/amass/amass_Linux_${ARCH_SUFFIX}/amass /tools/ && \
    rm -rf /tmp/amass "amass_Linux_${ARCH_SUFFIX}.zip"

# Build masscan and massdns from source (no pre-built releases)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/robertdavidgraham/masscan.git /tmp/masscan \
    && cd /tmp/masscan && make -j$(nproc) \
    && cp bin/masscan /tools/ \
    && rm -rf /tmp/masscan

RUN git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns \
    && cd /tmp/massdns && make -j$(nproc) \
    && cp bin/massdns /tools/ \
    && rm -rf /tmp/massdns

# Download waybackurls and assetfinder (smaller tools, compile quickly if needed)
RUN apt-get update && apt-get install -y --no-install-recommends golang \
    && rm -rf /var/lib/apt/lists/* \
    && go install github.com/tomnomnom/waybackurls@latest \
    && go install github.com/tomnomnom/assetfinder@latest \
    && cp /root/go/bin/* /tools/

RUN chmod +x /tools/*

# ============================================
# Stage 2: Final image with all dependencies
# ============================================
FROM base AS final

# Install system dependencies
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    curl \
    dnsutils \
    nmap \
    libpcap0.8 \
    chromium \
    chromium-driver \
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
    git

# Copy pre-built binaries
COPY --from=tool-downloader /tools/nuclei /usr/local/bin/
COPY --from=tool-downloader /tools/subfinder /usr/local/bin/
COPY --from=tool-downloader /tools/httpx /usr/local/bin/
COPY --from=tool-downloader /tools/dnsx /usr/local/bin/
COPY --from=tool-downloader /tools/naabu /usr/local/bin/
COPY --from=tool-downloader /tools/katana /usr/local/bin/
COPY --from=tool-downloader /tools/chaos-client /usr/local/bin/chaos
COPY --from=tool-downloader /tools/tlsx /usr/local/bin/
COPY --from=tool-downloader /tools/ffuf /usr/local/bin/
COPY --from=tool-downloader /tools/amass /usr/local/bin/
COPY --from=tool-downloader /tools/masscan /usr/local/bin/
COPY --from=tool-downloader /tools/massdns /usr/local/bin/
COPY --from=tool-downloader /tools/waybackurls /usr/local/bin/
COPY --from=tool-downloader /tools/assetfinder /usr/local/bin/

RUN chmod +x /usr/local/bin/*

# Install EyeWitness
RUN git clone --depth 1 https://github.com/RedSiege/EyeWitness.git /opt/EyeWitness \
    && cd /opt/EyeWitness \
    && python3 -m venv eyewitness-venv \
    && ./eyewitness-venv/bin/pip install --upgrade pip \
    && ./eyewitness-venv/bin/pip install selenium netaddr rapidfuzz psutil \
    && chmod +x Python/EyeWitness.py

ENV EYEWITNESS_PATH="/opt/EyeWitness/Python/EyeWitness.py"
ENV EYEWITNESS_VENV="/opt/EyeWitness/eyewitness-venv/bin/python"
ENV SCREENSHOTS_DIR="/app/data/screenshots"

# Install Python dependencies (install BEFORE copying code for better caching)
COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r requirements.txt

# Install ParamSpider
RUN pip install paramspider || echo "ParamSpider installation skipped"

# Update nuclei templates
RUN nuclei -update-templates || true

# Copy application code LAST (changes most frequently)
COPY . .

# Create non-root user
RUN adduser --disabled-password --gecos '' appuser \
    && chown -R appuser:appuser /app \
    && mkdir -p /home/appuser/.config/nuclei \
    && cp -r /root/.config/nuclei/* /home/appuser/.config/nuclei/ 2>/dev/null || true \
    && chown -R appuser:appuser /home/appuser \
    && mkdir -p /app/data/screenshots \
    && chown -R appuser:appuser /app/data \
    && chown -R appuser:appuser /opt/EyeWitness

USER appuser
ENV PATH="/usr/local/bin:${PATH}"

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
