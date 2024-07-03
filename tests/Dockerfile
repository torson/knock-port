FROM python:3.9.19-slim

RUN apt-get update && \
    echo "install system network utils" && \
    apt-get -y install iputils-ping net-tools telnet iproute2 procps dnsutils && \
    echo "install system utils" && \
    apt-get -y install procps
    # apt-get clean && \
    # rm -rf /var/lib/apt/lists/*

RUN echo "install iptables and nftables, curl" && \
    apt-get -y install iptables nftables curl

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


CMD ["sh", "-c", "echo 'keeping service up ...' && tail -f /dev/null"]
