ARG VYOS_ROLLING_VERSION=none
FROM vyos:${VYOS_ROLLING_VERSION}

RUN echo 'alias ll="ls -alF"' >> ~/.bashrc && \
    echo "Installing python-pip3" && \
    echo "deb http://deb.debian.org/debian/ bookworm main contrib non-free non-free-firmware" > /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y python3-pip python3-venv sudo

# set up knockport user, create venv (for testing with --run-with-sudo argument)
RUN adduser --disabled-password --gecos "" knockport && \
    usermod -a -G vyattacfg knockport && \
    echo "knockport ALL=NOPASSWD: /usr/sbin/iptables *" > /etc/sudoers.d/knockport && \
    echo "knockport ALL=NOPASSWD: /usr/sbin/nft *" >> /etc/sudoers.d/knockport && \
    mkdir -p /home/knockport && \
    chown knockport:users /home/knockport && \
    python3 -m venv /home/knockport/venv && \
    chown -R knockport:users /home/knockport/venv

# create venv for root user
# RUN python3 -m venv /root/venv

COPY requirements.txt /app/requirements.txt

RUN echo "installing KnockPort requirements" && \
    echo "for user knockport" && \
    chown knockport:users /app/requirements.txt && \
    su - knockport -c "cd /app && ~/venv/bin/pip install --no-cache-dir -r requirements.txt" && \
    echo "for user root" && \
    cp -R /home/knockport/venv /root/ && \
    chown -R root:root /root
