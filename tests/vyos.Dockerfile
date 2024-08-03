FROM vyos:1.5-rolling-202405260021

RUN echo 'alias ll="ls -alF"' >> ~/.bashrc && \
    echo "Installing python-pip3" && \
    echo "deb http://deb.debian.org/debian/ bookworm main contrib non-free non-free-firmware" > /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y python3-pip python3-venv

COPY requirements.txt /app/requirements.txt

RUN echo "installing KnockPort requirements" && \
    python3 -m venv ~/venv && \
    cd /app && \
    ~/venv/bin/pip install --no-cache-dir -r requirements.txt
