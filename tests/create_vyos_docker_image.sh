#!/bin/bash
set -e

if [ -z ${VYOS_ROLLING_VERSION} ]; then
    echo "ERROR: envvar VYOS_ROLLING_VERSION needs to be set , exiting ..."
    exit 1
fi

cd $(dirname $0)

if docker images | grep vyos | grep ${VYOS_ROLLING_VERSION} ; then
    echo "Docker image is already in the local cache"
    exit
fi

if [ -f .env ]; then
    source .env
fi

# https://docs.vyos.io/en/latest/installation/virtual/docker.html
if [ ! -f vyos-${VYOS_ROLLING_VERSION}-generic-amd64.iso ]; then
    wget https://github.com/vyos/vyos-nightly-build/releases/download/${VYOS_ROLLING_VERSION}/vyos-${VYOS_ROLLING_VERSION}-generic-amd64.iso
fi
mkdir -p vyos-docker ; cd vyos-docker
ln -s ../vyos-${VYOS_ROLLING_VERSION}-generic-amd64.iso vyos-${VYOS_ROLLING_VERSION}-generic-amd64.iso

mkdir -p rootfs
sudo mount -o loop vyos-${VYOS_ROLLING_VERSION}-generic-amd64.iso rootfs

# assuming we're running Debian flavour
if ! dpkg -l | grep squashfs-tools ; then
    sudo apt-get install -y squashfs-tools
fi
mkdir unsquashfs
sudo unsquashfs -f -d unsquashfs/ rootfs/live/filesystem.squashfs
sudo tar -C unsquashfs -c . | docker import - vyos:${VYOS_ROLLING_VERSION}

# cleanup
sudo umount rootfs
cd ..
sudo rm -rf vyos-docker



## start the container and get to the console
# docker run -d --rm --name vyos --privileged -v /lib/modules:/lib/modules vyos:${VYOS_ROLLING_VERSION} /sbin/init
# docker exec -ti vyos su - vyos
