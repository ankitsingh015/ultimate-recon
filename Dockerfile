FROM kalilinux/kali-rolling:latest

LABEL description="Ultimate Recon - Complete Bug Bounty Reconnaissance Toolkit"
LABEL version="1.0"
LABEL maintainer="ultimate-recon"

ENV DEBIAN_FRONTEND=noninteractive
ENV GOROOT=/usr/local/go
ENV GOPATH=/root/go
ENV PATH=$PATH:$GOROOT/bin:$GOPATH/bin:/root/.local/bin:/root/.cargo/bin:/opt/venv/bin
ENV PIP_BREAK_SYSTEM_PACKAGES=1
ENV NUCLEI_HOME=/root/nuclei-templates

SHELL ["/bin/bash", "-c"]

RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        ca-certificates curl wget git jq yq \
        build-essential gcc make python3 python3-pip python3-venv \
        ruby ruby-dev golang-go perl nodejs npm \
        nmap masscan whois dnsutils netcat-openbsd \
        libpcap-dev libssl-dev zlib1g-dev \
        xvfb firefox-esr chromium \
        openssh-client sshpass \
        unzip p7zip-full xz-utils \
        sqlmap wafw00f \
        dnsrecon dnsenum \
        whatweb \
        commix \
        ffuf \
        wpscan \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --upgrade pip setuptools wheel && \
    pip3 install --no-cache-dir \
        requests beautifulsoup4 lxml \
        jinja2 pyyaml aiohttp aiofiles \
        tqdm colorama rich \
        trufflehog \
        arjun \
        corsy \
        CORScanner \
        bxss \
        dalfox \
        xsschecker \
        xsscope \
        ssrfmap \
        gopherus \
        jwt_tool \
        s3scanner \
        cloud-enum \
        paramspider \
        waymore \
        uro \
        anewer \
        urldedupe \
        gf \
        dirsearch \
        interactsh \
        dnsgen \
        nuclei \
        httpx-toolkit \
        subfinder \
        puredns \
        shuffledns

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
    go install -v github.com/coffinxp/loxs@latest

RUN curl -sL https://raw.githubusercontent.com/tomnomnom/gf/master/gf-completion.bash > /etc/bash_completion.d/gf && \
    mkdir -p ~/.gf && \
    git clone https://github.com/coffinxp/GFpattren.git /tmp/gf-patterns && \
    cp /tmp/gf-patterns/*.json ~/.gf/ 2>/dev/null; \
    git clone https://github.com/1ndianl33t/Gf-Patterns.git /tmp/gf-more && \
    cp /tmp/gf-more/*.json ~/.gf/ 2>/dev/null; \
    rm -rf /tmp/gf-patterns /tmp/gf-more

RUN git clone https://github.com/coffinxp/nuclei-templates /root/nuclei-templates 2>/dev/null || \
    git clone https://github.com/projectdiscovery/nuclei-templates /root/nuclei-templates && \
    nuclei -update-templates

RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists 2>/dev/null; \
    git clone https://github.com/coffinxp/payloads.git /opt/payloads 2>/dev/null; \
    git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git /opt/payloads-all-the-things 2>/dev/null

RUN git clone https://github.com/coffinxp/scripts.git /opt/scripts 2>/dev/null; \
    git clone https://github.com/EdOverflow/can-i-take-over-xyz.git /opt/can-i-take-over-xyz 2>/dev/null

RUN pip3 install --no-cache-dir \
        secretfinder \
        linkfinder \
        JSParser \
        jsfscan \
        jsubfinder \
        xsscope \
        xxeinjector \
        sstimap \
        gitdumper \
        gitleaks \
        gitgraber \
        graphqlmap \
        openredirex

RUN mkdir /opt/venv && \
    python3 -m venv /opt/venv && \
    source /opt/venv/bin/activate && \
    pip3 install --no-cache-dir \
        secretfinder linkfinder jsparser jsfscan \
        jsubfinder trufflehog xxeinjector sstimap \
        gitdumper gitleaks gitgraber graphqlmap openredirex

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
