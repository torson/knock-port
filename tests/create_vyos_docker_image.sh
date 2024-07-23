#!/bin/bash

if [ -z ${VYOS_ROLLING_VERSION} ]; then
    echo "ERROR: envvar VYOS_ROLLING_VERSION needs to be set , exiting ..."
    exit 1
fi

if docker images | grep vyos | grep ${VYOS_ROLLING_VERSION} ; then
    echo "Docker image is already in the local cache"
    exit
fi

# https://docs.vyos.io/en/latest/installation/virtual/docker.html
mkdir vyos-docker && cd vyos-docker
curl -o vyos-${VYOS_ROLLING_VERSION}-amd64.iso https://github.com/vyos/vyos-rolling-nightly-builds/releases/download/${VYOS_ROLLING_VERSION}/vyos-${VYOS_ROLLING_VERSION}-amd64.iso

mkdir rootfs
sudo mount -o loop vyos-${VYOS_ROLLING_VERSION}-amd64.iso rootfs

# assuming you're running Debian flavour
sudo apt-get install -y squashfs-tools
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
