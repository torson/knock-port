FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && \
    echo "install system network utils" && \
    apt-get -y install iputils-ping net-tools telnet iproute2 procps dnsutils && \
    echo "install system utils" && \
    apt-get -y install procps
    # apt-get clean && \
    # rm -rf /var/lib/apt/lists/*

RUN echo "install iptables and nftables" && \
    apt-get -y install iptables nftables

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

CMD ["sh", "-c", "echo 'keeping service up ...' && tail -f /dev/null"]
