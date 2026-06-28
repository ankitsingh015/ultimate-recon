# Stage 1: Builder — compile Go tools only
FROM kalilinux/kali-rolling:latest AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV GOROOT=/usr/local/go
ENV GOPATH=/root/go
ENV PATH=$PATH:$GOROOT/bin:$GOPATH/bin

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl wget git \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sL https://go.dev/dl/go1.22.0.linux-amd64.tar.gz | tar -C /usr/local -xzf -

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/findomain/findomain@latest && \
    go install -v github.com/owasp-amass/amass/v4/...@master && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest && \
    go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest && \
    go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest && \
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest && \
    go install -v github.com/tomnomnom/qsreplace@latest && \
    go install -v github.com/tomnomnom/gf@latest && \
    go install -v github.com/tomnomnom/unfurl@latest && \
    go install -v github.com/tomnomnom/anew@latest && \
    go install -v github.com/hakluke/hakrawler@latest && \
    go install -v github.com/tomnomnom/meg@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/lc/subjs@latest && \
    go install -v github.com/hakluke/hakrawler@latest && \
    go install -v github.com/hakluke/haktrails@latest && \
    go install -v github.com/sensepost/gowitness@latest && \
    go install -v github.com/michenriksen/aquatone@latest && \
    go install -v github.com/gwen001/github-subdomains@latest && \
    go install -v github.com/incogbyte/shosubgo@latest && \
    go install -v github.com/003random/getJS@latest && \
    go install -v github.com/pentestpad/subzy@latest && \
    go install -v github.com/KathanP19/urlfinder@latest && \
    go install -v github.com/Josue87/gospider@latest && \
    go install -v github.com/s0md3v/rustscan@latest && \
    go install -v github.com/dwisiswant0/unew@latest && \
    go install -v github.com/d3mondev/puredns/v2@latest && \
    go install -v github.com/nyxiereal/s3scanner@latest && \
    go install -v github.com/coffinxp/loxs@latest && \
    go install -v github.com/devanshbatham/dalfox/v2@latest && \
    go install -v github.com/gitleaks/gitleaks@latest

# Stage 2: Final — minimal runtime image
FROM kalilinux/kali-rolling:latest

LABEL description="Ultimate Recon - Complete Bug Bounty Reconnaissance Toolkit"
LABEL version="1.0"
LABEL maintainer="ultimate-recon"

ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/root/go
ENV PATH=$PATH:$GOPATH/bin:/root/.local/bin
ENV PIP_BREAK_SYSTEM_PACKAGES=1
ENV NUCLEI_HOME=/root/nuclei-templates

SHELL ["/bin/bash", "-c"]

# Runtime packages only (no build tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl wget git jq yq \
    python3 python3-pip \
    nmap masscan whois dnsutils netcat-openbsd \
    libpcap-dev libssl-dev zlib1g-dev \
    xvfb chromium \
    openssh-client sshpass \
    unzip xz-utils \
    sqlmap wafw00f \
    dnsrecon dnsenum \
    whatweb commix ffuf wpscan \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /var/cache/apt/archives/*

# Copy Go binaries from builder (no Go compiler in final image)
COPY --from=builder /root/go/bin /root/go/bin

# Python packages (pure pip, no compilation needed)
RUN pip3 install --upgrade pip setuptools wheel --ignore-installed && \
    pip3 install --no-cache-dir --ignore-installed \
        requests beautifulsoup4 lxml \
        jinja2 pyyaml aiohttp aiofiles \
        tqdm colorama rich \
        trufflehog arjun waymore uro dirsearch \
    && rm -rf /root/.cache/pip

# GF patterns
RUN curl -sL https://raw.githubusercontent.com/tomnomnom/gf/master/gf-completion.bash > /etc/bash_completion.d/gf && \
    mkdir -p ~/.gf && \
    git clone https://github.com/coffinxp/GFpattren.git /tmp/gf-patterns 2>/dev/null && \
    cp /tmp/gf-patterns/*.json ~/.gf/ 2>/dev/null; \
    git clone https://github.com/1ndianl33t/Gf-Patterns.git /tmp/gf-more 2>/dev/null && \
    cp /tmp/gf-more/*.json ~/.gf/ 2>/dev/null; \
    rm -rf /tmp/gf-patterns /tmp/gf-more 2>/dev/null

# Nuclei templates
RUN git clone https://github.com/coffinxp/nuclei-templates /root/nuclei-templates 2>/dev/null || \
    git clone https://github.com/projectdiscovery/nuclei-templates /root/nuclei-templates && \
    nuclei -update-templates 2>/dev/null || true

# Wordlists and payloads
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists 2>/dev/null; \
    git clone https://github.com/coffinxp/payloads.git /opt/payloads 2>/dev/null; \
    git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git /opt/payloads-all-the-things 2>/dev/null

RUN git clone https://github.com/coffinxp/scripts.git /opt/scripts 2>/dev/null; \
    git clone https://github.com/EdOverflow/can-i-take-over-xyz.git /opt/can-i-take-over-xyz 2>/dev/null

# GitHub Python tools (install from source)
RUN \
    git clone https://github.com/s0md3v/Corsy.git /opt/Corsy 2>/dev/null && \
        cd /opt/Corsy && pip3 install -r requirements.txt 2>/dev/null; \
    git clone https://github.com/chenjj/CORScanner.git /opt/CORScanner 2>/dev/null && \
        cd /opt/CORScanner && pip3 install -r requirements.txt 2>/dev/null; \
    git clone https://github.com/anspwn/bxss.git /opt/bxss 2>/dev/null && \
        cd /opt/bxss && pip3 install . 2>/dev/null; \
    git clone https://github.com/coffinxp/xsscope.git /opt/xsscope 2>/dev/null && \
        cd /opt/xsscope && pip3 install . 2>/dev/null; \
    git clone https://github.com/swisskyrepo/SSRFmap.git /opt/SSRFmap 2>/dev/null && \
        cd /opt/SSRFmap && pip3 install -r requirements.txt 2>/dev/null; \
    git clone https://github.com/tarunkant/Gopherus.git /opt/gopherus 2>/dev/null && \
        cd /opt/gopherus && pip3 install . 2>/dev/null; \
    git clone https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool 2>/dev/null && \
        cd /opt/jwt_tool && pip3 install -r requirements.txt 2>/dev/null; \
    git clone https://github.com/coffinxp/cloud-enum.git /opt/cloud-enum 2>/dev/null && \
        cd /opt/cloud-enum && pip3 install . 2>/dev/null; \
    git clone https://github.com/devanshbatham/ParamSpider.git /opt/ParamSpider 2>/dev/null && \
        cd /opt/ParamSpider && pip3 install -r requirements.txt 2>/dev/null; \
    git clone https://github.com/coffinxp/anewer.git /opt/anewer 2>/dev/null && \
        cd /opt/anewer && pip3 install . 2>/dev/null; \
    git clone https://github.com/ProjectAnte/dnsgen.git /opt/dnsgen 2>/dev/null && \
        cd /opt/dnsgen && pip3 install -r requirements.txt 2>/dev/null; \
    git clone https://github.com/s0md3v/XSStrike.git /opt/XSStrike 2>/dev/null && \
        cd /opt/XSStrike && pip3 install -r requirements.txt 2>/dev/null; \
    git clone https://github.com/enjoiz/XXEinjector.git /opt/XXEinjector 2>/dev/null; \
    git clone https://github.com/swisskyrepo/SSTImap.git /opt/SSTImap 2>/dev/null && \
        cd /opt/SSTImap && pip3 install -r requirements.txt 2>/dev/null; \
    git clone https://github.com/internetwache/GitTools.git /opt/GitTools 2>/dev/null; \
    git clone https://github.com/coffinxp/GitGraber.git /opt/GitGraber 2>/dev/null && \
        cd /opt/GitGraber && pip3 install -r requirements.txt 2>/dev/null; \
    git clone https://github.com/swisskyrepo/GraphQLmap.git /opt/GraphQLmap 2>/dev/null && \
        cd /opt/GraphQLmap && pip3 install -r requirements.txt 2>/dev/null; \
    git clone https://github.com/coffinxp/openredirex.git /opt/openredirex 2>/dev/null && \
        cd /opt/openredirex && pip3 install . 2>/dev/null; \
    git clone https://github.com/ameenmaali/urldedupe.git /opt/urldedupe 2>/dev/null; \
    echo "GitHub tools installation complete"

RUN git clone https://github.com/m4ll0k/SecretFinder.git /opt/SecretFinder && \
    cd /opt/SecretFinder && pip3 install -r requirements.txt 2>/dev/null; \
    git clone https://github.com/GerbenJavado/LinkFinder.git /opt/LinkFinder && \
    cd /opt/LinkFinder && pip3 install -r requirements.txt 2>/dev/null; \
    git clone https://github.com/0x240x23elu/JSParser.git /opt/JSParser && \
    cd /opt/JSParser && python3 setup.py install 2>/dev/null; \
    git clone https://github.com/m4ll0k/JSFScan.git /opt/JSFScan && \
    cd /opt/JSFScan && pip3 install -r requirements.txt 2>/dev/null

RUN git clone https://github.com/dwisiswant0/jsubfinder.git /opt/jsubfinder && \
    cd /opt/jsubfinder && wget https://raw.githubusercontent.com/dwisiswant0/jsubfinder/master/.jsubfinder.json 2>/dev/null

RUN mkdir -p /opt/custom-wordlists && \
    curl -sL "https://raw.githubusercontent.com/coffinxp/payloads/main/coffin%40wp-fuzz.txt" \
        -o /opt/custom-wordlists/wp-fuzz.txt 2>/dev/null; \
    curl -sL "https://raw.githubusercontent.com/coffinxp/payloads/main/lfi.txt" \
        -o /opt/custom-wordlists/lfi.txt 2>/dev/null; \
    curl -sL "https://raw.githubusercontent.com/coffinxp/payloads/main/xss-payloads.txt" \
        -o /opt/custom-wordlists/xss-payloads.txt 2>/dev/null; \
    curl -sL "https://raw.githubusercontent.com/coffinxp/payloads/main/ssrf-payloads.txt" \
        -o /opt/custom-wordlists/ssrf-payloads.txt 2>/dev/null; \
    curl -sL "https://raw.githubusercontent.com/coffinxp/payloads/main/open-redirect.txt" \
        -o /opt/custom-wordlists/open-redirect.txt 2>/dev/null; \
    curl -sL "https://raw.githubusercontent.com/coffinxp/payloads/main/sqli-payloads.txt" \
        -o /opt/custom-wordlists/sqli-payloads.txt 2>/dev/null

COPY src/ /opt/ultimate-recon/src/
COPY config/ /opt/ultimate-recon/config/
COPY run.sh setup.sh /opt/ultimate-recon/

RUN chmod +x /opt/ultimate-recon/run.sh /opt/ultimate-recon/setup.sh && \
    ln -sf /opt/ultimate-recon/run.sh /usr/local/bin/ultimate-recon

RUN nuclei -update-templates 2>/dev/null || true

WORKDIR /opt/ultimate-recon

ENTRYPOINT ["python3", "/opt/ultimate-recon/src/orchestrator.py"]
CMD ["--help"]
