FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# ── System dependencies ──────────────────────────────────────────────
RUN apt-get update && apt-get install -y \
    curl wget git unzip jq python3 python3-pip python3-venv \
    dnsutils nmap masscan libpcap-dev whois \
    nikto ruby ruby-dev build-essential libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# ── Go toolchain (for ProjectDiscovery + Praetorian tools) ──────────
# Go 1.25+ required by Praetorian pius; older tools build fine on 1.25.
ARG GO_VERSION=1.25.0
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-$(dpkg --print-architecture).tar.gz" \
    | tar -C /usr/local -xz

# ── ProjectDiscovery tools ───────────────────────────────────────────
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest

# ── Additional Go-based security tools ───────────────────────────────
RUN go install -v github.com/owasp-amass/amass/v4/...@master \
    && go install -v github.com/tomnomnom/waybackurls@latest \
    && go install -v github.com/lc/gau/v2/cmd/gau@latest \
    && go install -v github.com/ffuf/ffuf/v2@latest \
    && go install -v github.com/s0md3v/smap/cmd/smap@latest

# ── Praetorian tools (Aegis Vanguard add-ons) ───────────────────────
# pius: organizational asset discovery (24+ OSINT plugins, 5 RIRs)
# titus: secrets scanner (487 rules, optional live validation)
RUN go install -v github.com/praetorian-inc/pius/cmd/pius@latest \
    && go install -v github.com/praetorian-inc/titus/cmd/titus@latest

# ── gitleaks ─────────────────────────────────────────────────────────
ARG GITLEAKS_VERSION=8.18.4
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then GL_ARCH="x64"; else GL_ARCH="$ARCH"; fi && \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz" \
    | tar -C /usr/local/bin -xz gitleaks

# ── testssl.sh ───────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh \
    && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# ── XSStrike ─────────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/s0md3v/XSStrike.git /opt/xsstrike

# ── CMSeeK ───────────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/Tuhinshubhra/CMSeeK.git /opt/cmseek

# ── Arjun (HTTP parameter discovery) ────────────────────────────────
RUN python3 -m pip install --break-system-packages arjun

# ── WhatWeb ──────────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb \
    && ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb

# ── wafw00f ──────────────────────────────────────────────────────────
RUN python3 -m pip install --break-system-packages wafw00f

# ── sslyze ───────────────────────────────────────────────────────────
RUN python3 -m pip install --break-system-packages sslyze

# ── sqlmap ───────────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# ── WPScan (Ruby gem) ───────────────────────────────────────────────
RUN gem install wpscan --no-document

# ── Nuclei templates ────────────────────────────────────────────────
RUN nuclei -update-templates 2>/dev/null || true

# ── Wordlists for fuzzing ───────────────────────────────────────────
RUN mkdir -p /usr/share/wordlists/dirb && \
    curl -fsSL -o /usr/share/wordlists/dirb/common.txt \
    https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt

# ── Python dependencies for the bridge ──────────────────────────────
# Build from monorepo root so shared asm_scanner_core is available:
#   docker build -f nanoclaw-agent/Dockerfile .
WORKDIR /agent
COPY backend/packages/asm_scanner_core /packages/asm_scanner_core
RUN python3 -m pip install --break-system-packages -e /packages/asm_scanner_core
COPY nanoclaw-agent/requirements.txt ./
RUN python3 -m pip install --break-system-packages -r requirements.txt

# ── Playwright + Chromium for browser-based dynamic testing ─────────
RUN playwright install --with-deps chromium

# ── Agent files ─────────────────────────────────────────────────────
COPY nanoclaw-agent/asm_bridge.py nanoclaw-agent/scanners.py nanoclaw-agent/healthcheck.py nanoclaw-agent/CLAUDE.md \
     nanoclaw-agent/run_pentest.py nanoclaw-agent/reporter.py ./
COPY nanoclaw-agent/agent/ ./agent/

# Default env vars (override at runtime)
ENV ASM_API_URL=""
ENV ASM_API_KEY=""
ENV ASM_AGENT_ID="aegis-vanguard"
ENV ANTHROPIC_API_KEY=""
# AEGIS_* env vars are preferred; NANOCLAW_* kept as aliases for backward compat.
ENV AEGIS_MODEL="claude-sonnet-4-20250514"
ENV AEGIS_GUARDRAILS="true"
ENV AEGIS_TRACING="true"

HEALTHCHECK --interval=60s --timeout=10s --retries=3 \
    CMD python3 /agent/healthcheck.py --quick || exit 1

CMD ["bash"]
