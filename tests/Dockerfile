FROM python:3.9.19-slim

RUN apt-get update && \
    echo "install system network utils" && \
    apt-get -y install iputils-ping net-tools telnet iproute2 procps dnsutils && \
    echo "install system utils" && \
    apt-get -y install procps sudo
    # apt-get clean && \
    # rm -rf /var/lib/apt/lists/*

RUN echo "install iptables and nftables, curl" && \
    apt-get -y install iptables nftables curl vim

RUN adduser --disabled-password ubuntu
RUN echo "ubuntu ALL=NOPASSWD: /usr/sbin/iptables *" > /etc/sudoers.d/knockport && \
    echo "ubuntu ALL=NOPASSWD: /usr/sbin/nft *" >> /etc/sudoers.d/knockport

# Add knockport user for testing --run-with-sudo feature
RUN adduser --disabled-password knockport
RUN echo "knockport ALL=NOPASSWD: /usr/sbin/iptables *" >> /etc/sudoers.d/knockport && \
    echo "knockport ALL=NOPASSWD: /usr/sbin/nft *" >> /etc/sudoers.d/knockport

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

CMD ["sh", "-c", "echo 'keeping service up ...' && tail -f /dev/null"]
