#!/bin/bash

RUN_TESTS_ROUTING_TYPE_IPTABLES=true
RUN_TESTS_ROUTING_TYPE_NFTABLES=false
RUN_TESTS_ROUTING_TYPE_VYOS=false


log() {
    echo -e "\n--> $(date) : $@"
}

VERBOSE=true
run_command() {
	if [ "${VERBOSE}"x = "true"x ]; then
		echo -e "\n--> $(date) : Running: $@"
	fi
	if [ "${RUN_COMMAND_OUTPUT_GREP_PATTERN_ERROR}"x != ""x ]; then
		$@ 2>&1 | tee -a /tmp/$(basename $0).out
		FIRST_COMMAND_STATUS=${PIPESTATUS[0]}
		if [ "${FIRST_COMMAND_STATUS}" != "0" ]; then
			echo -e "\n\n--> $(date) : ERROR (run_command): command exited with exit code $CMD_EXIT_CODE "
			exit $FIRST_COMMAND_STATUS
		fi
		if grep "${RUN_COMMAND_OUTPUT_GREP_PATTERN_ERROR}" /tmp/$(basename $0).out ; then
			echo -e "\n\n--> $(date) : ERROR (run_command): '$@' failed with pattern '${RUN_COMMAND_OUTPUT_GREP_PATTERN_ERROR}' , exiting with status 1"
			rm /tmp/$(basename $0).out
			exit 1
		fi
		rm /tmp/$(basename $0).out
	else
		$@
	fi
    CMD_EXIT_CODE=$?
    if [ "$CMD_EXIT_CODE" != "0" ]; then
        echo -e "\n\n--> $(date) : ERROR (run_command): command exited with exit code $CMD_EXIT_CODE "
        exit $CMD_EXIT_CODE
    fi
}

if echo $0 | grep -P "\./" >/dev/null 2>&1 ; then
    # run in current folder
    SCRIPT_PATH=$(pwd)/$(echo $0 | sed -r 's/\.\///')
elif echo $0 | grep -P "^/" >/dev/null 2>&1 ; then
    # run with full path
    SCRIPT_PATH=$0
else
    # run with relative path
    SCRIPT_PATH=$(pwd)/$0
fi
BASE_DIR_PATH=$(dirname ${SCRIPT_PATH} | xargs dirname)
cd ${BASE_DIR_PATH}

log "pwd=$(pwd)"
log "BASE_DIR_PATH=${BASE_DIR_PATH}"
log "RUN_TESTS_ROUTING_TYPE_IPTABLES=${RUN_TESTS_ROUTING_TYPE_IPTABLES}"
log "RUN_TESTS_ROUTING_TYPE_NFTABLES=${RUN_TESTS_ROUTING_TYPE_NFTABLES}"
log "RUN_TESTS_ROUTING_TYPE_VYOS=${RUN_TESTS_ROUTING_TYPE_VYOS}"

if [ ! -f ${BASE_DIR_PATH}/tests/knock-port.testing.pem ] ; then
    log "generating testing certificate"
    echo "


    Testing

    knock-port.testing

    " | openssl req -x509 -newkey rsa:4096 -keyout tests/knock-port.testing.key -out tests/knock-port.testing.pem -days 3650 -nodes
else
    log "${BASE_DIR_PATH}/tests/knock-port.testing.pem already exists."
fi

# Get the test_app port from config.test.yaml
TEST_SERVICE_PORT=$(grep port ${BASE_DIR_PATH}/tests/config.test.yaml | awk '{print $2}' | head -n 1)
KNOCKPORT_PORT_HTTP=8080
KNOCKPORT_PORT_HTTPS=8443

if [[ "${RUN_TESTS_ROUTING_TYPE_IPTABLES}"  = "true" || "${RUN_TESTS_ROUTING_TYPE_NFTABLES}"  = "true" ]]; then
    # Build the Docker image
    run_command docker build -f tests/Dockerfile -t port-knock-server .
fi

if ! docker ps | grep port-knock-server-backend; then
    run_command docker run --rm -d --name port-knock-server-backend port-knock-server python -m http.server ${TEST_SERVICE_PORT}
    export BACKEND_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' port-knock-server-backend)
fi
# generating tests/config.test.yaml
envsubst < ${BASE_DIR_PATH}/tests/config.test.tmpl.yaml > ${BASE_DIR_PATH}/tests/config.test.yaml

### 1. iptables
if [[ "${RUN_TESTS_ROUTING_TYPE_IPTABLES}"  = "true" ]]; then
    log "### testing --routing-type iptables"

    # Stop and remove the Docker container
    if docker stop -t 1 port-knock-server ; then
        # vyos container can take a few seconds to be stopped and removed
        sleep 5
    fi

    # Run the server in a Docker container using host network
    run_command docker run --rm -d --cap-add=NET_ADMIN -v ${BASE_DIR_PATH}:/app -p ${KNOCKPORT_PORT_HTTP}:${KNOCKPORT_PORT_HTTP} -p ${KNOCKPORT_PORT_HTTPS}:${KNOCKPORT_PORT_HTTPS} -p ${TEST_SERVICE_PORT}:${TEST_SERVICE_PORT} --name port-knock-server port-knock-server python -m http.server ${TEST_SERVICE_PORT}

    log "installing requirements"
    log "docker exec port-knock-server bash -c \
        'pip install --no-cache-dir -r requirements.txt'"
    docker exec port-knock-server bash -c \
        'pip install --no-cache-dir -r requirements.txt'

    log "Drop access to the testing service port"
    run_command docker exec port-knock-server iptables -A INPUT -p tcp --dport ${TEST_SERVICE_PORT} -j DROP

    log "Starting KnockPort"
    log docker exec port-knock-server bash -c \
        'python src/server.py -c tests/config.test.yaml --routing-type iptables --http-port '${KNOCKPORT_PORT_HTTP}' --https-port '${KNOCKPORT_PORT_HTTPS}' --cert tests/knock-port.testing.pem --key tests/knock-port.testing.key > tests/run_docker_tests.server.iptables.log 2>&1 &'
    docker exec port-knock-server bash -c \
        'python src/server.py -c tests/config.test.yaml --routing-type iptables --http-port '${KNOCKPORT_PORT_HTTP}' --https-port '${KNOCKPORT_PORT_HTTPS}' --cert tests/knock-port.testing.pem --key tests/knock-port.testing.key > tests/run_docker_tests.server.iptables.log 2>&1 &'
    sleep 3

    # Run the tests
    run_command python ${BASE_DIR_PATH}/tests/tests.py

    run_command docker stop -t 1 port-knock-server
fi


### 2. nftables
if [[ "${RUN_TESTS_ROUTING_TYPE_NFTABLES}"  = "true" ]]; then
    log "### testing --routing-type nftables"

    # Stop and remove the Docker container
    if docker stop -t 1 port-knock-server ; then
        # vyos container can take a few seconds to be stopped and removed
        sleep 5
    fi

    # Run the server in a Docker container using host network
    run_command docker run --rm -d --cap-add=NET_ADMIN -v ${BASE_DIR_PATH}:/app -p ${KNOCKPORT_PORT_HTTP}:${KNOCKPORT_PORT_HTTP} -p ${KNOCKPORT_PORT_HTTPS}:${KNOCKPORT_PORT_HTTPS} -p ${TEST_SERVICE_PORT}:${TEST_SERVICE_PORT} --name port-knock-server port-knock-server python -m http.server ${TEST_SERVICE_PORT}

    log "installing requirements"
    log "docker exec port-knock-server bash -c \
        'pip install --no-cache-dir -r requirements.txt'"
    docker exec port-knock-server bash -c \
        'pip install --no-cache-dir -r requirements.txt'

    log "Create nftables table and chain"
    run_command docker exec port-knock-server \
        nft add table ip filter
    log docker exec port-knock-server \
        nft add chain ip filter INPUT '{ type filter hook input priority filter; policy accept; }'
    docker exec port-knock-server \
        nft add chain ip filter INPUT '{ type filter hook input priority filter; policy accept; }'
    log docker exec port-knock-server \
        nft add chain ip filter OUTPUT '{ type filter hook output priority filter; policy accept; }'
    docker exec port-knock-server \
        nft add chain ip filter OUTPUT '{ type filter hook output priority filter; policy accept; }'

    log "Drop access to the testing service port"
    run_command docker exec port-knock-server \
        nft add rule ip filter INPUT tcp dport ${TEST_SERVICE_PORT} drop
    sleep 1

    #   Docs:
    #     https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/getting-started-with-nftables_configuring-and-managing-networking
    #     https://unix.stackexchange.com/questions/753858/nftables-deleting-a-rule-without-passing-handle-similar-to-iptables-delete
    log "Starting KnockPort"
    log docker exec port-knock-server bash -c \
        'python src/server.py -c tests/config.test.yaml --routing-type nftables --nftables-table filter --nftables-chain-input INPUT --http-port '${KNOCKPORT_PORT_HTTP}' --https-port '${KNOCKPORT_PORT_HTTPS}' --cert tests/knock-port.testing.pem --key tests/knock-port.testing.key > tests/run_docker_tests.server.nftables.log 2>&1 &'
    docker exec port-knock-server bash -c \
        'python src/server.py -c tests/config.test.yaml --routing-type nftables --nftables-table filter --nftables-chain-input INPUT --http-port '${KNOCKPORT_PORT_HTTP}' --https-port '${KNOCKPORT_PORT_HTTPS}' --cert tests/knock-port.testing.pem --key tests/knock-port.testing.key > tests/run_docker_tests.server.nftables.log 2>&1 &'
    sleep 3

    # Run the tests
    run_command python ${BASE_DIR_PATH}/tests/tests.py

    run_command docker stop -t 1 port-knock-server
fi


### 3. vyos
if [[ "${RUN_TESTS_ROUTING_TYPE_VYOS}"  = "true" ]]; then
    log "### testing --routing-type vyos"

    export VYOS_ROLLING_VERSION=1.5-rolling-202405260021
    bash -x ${BASE_DIR_PATH}/tests/create_vyos_docker_image.sh || exit 1

    # Stop and remove the Docker container
    if docker stop -t 1 port-knock-server ; then
        # vyos container can take a few seconds to be stopped and removed
        sleep 5
    fi

    if ! docker ps | grep port-knock-server; then
        # https://docs.vyos.io/en/latest/installation/virtual/docker.html
        run_command docker run --rm -d --name port-knock-server --privileged -v ${BASE_DIR_PATH}:/app -v /lib/modules:/lib/modules -p ${KNOCKPORT_PORT_HTTP}:${KNOCKPORT_PORT_HTTP} -p ${KNOCKPORT_PORT_HTTPS}:${KNOCKPORT_PORT_HTTPS} -p ${TEST_SERVICE_PORT}:${TEST_SERVICE_PORT} vyos:${VYOS_ROLLING_VERSION} /sbin/init
        log "Sleeping 60s as VyOs takes a few seconds to initialize"
        sleep 60
    fi

    log "preparing VyOS"

    docker exec -u vyos port-knock-server vbash -c '
            source /opt/vyatta/etc/functions/script-template
            configure
            echo "Set up DNS"
            HOSTNAME=$(hostname)
            set system static-host-mapping host-name $HOSTNAME inet 127.0.0.1
            commit
            set system name-server 8.8.8.8
            set service dns forwarding listen-address 127.0.0.1
            set service dns forwarding allow-from 0.0.0.0/0
            commit
            exit
        '

    docker exec port-knock-server bash -c '
            echo alias\ ll="ls\ -alF" >> ~/.bashrc
            echo "Installing python-pip3"
            echo "deb http://deb.debian.org/debian/ bookworm main contrib non-free non-free-firmware" > /etc/apt/sources.list
            apt-get update
            apt-get install -y python3-pip python3-venv
            echo "installing KnockPort requirements"
            python3 -m venv ~/venv
            cd /app
            ~/venv/bin/pip install --no-cache-dir -r requirements.txt
            ~/venv/bin/python -m http.server '${TEST_SERVICE_PORT}' > tests/run_docker_tests.http-server.vyos.log 2>&1 &
        '

    log "Drop access to the testing service port"
    docker exec -u vyos port-knock-server vbash -c '
            source /opt/vyatta/etc/functions/script-template
            configure
            echo "Create chain and default DROP rule for IN-KnockPort"
            set firewall ipv4 name IN-KnockPort default-action drop
            set firewall ipv4 name IN-KnockPort rule 100 action drop
            set firewall ipv4 name IN-KnockPort rule 100 protocol tcp
            set firewall ipv4 name IN-KnockPort rule 100 destination port '${TEST_SERVICE_PORT}'
            set firewall ipv4 input filter rule 20 action jump
            set firewall ipv4 input filter rule 20 jump-target IN-KnockPort
            commit
        '

    # log "Setting up OpenVPN"
    # docker exec -u vyos port-knock-server vbash -c '
    #         source /opt/vyatta/etc/functions/script-template
    #         configure
    #         echo "Generate certificate for OpenVPN"
    #         echo -e "\n\n\n\n\n\n\n\n\n" | run generate pki ca install ca-1
    #         commit
    #         echo "generating server certificate" ; echo
    #         echo -e "\n\n\n\n\n\n\n\n\n\n\n\n" | run generate pki certificate sign ca-1 install srv-1
    #         commit
    #         echo -e "\ngenerating DH key , this takes a few seconds ...\n\n"
    #         echo -e "\n" | run generate pki dh install dh-1
    #         commit
    #         echo "Set up OpenVPN"
    #         set interfaces openvpn vtun0 local-port 1194
    #         set interfaces openvpn vtun0 mode server
    #         set interfaces openvpn vtun0 protocol tcp-passive
    #         set interfaces openvpn vtun0 encryption cipher aes256
    #         set interfaces openvpn vtun0 hash sha512
    #         set interfaces openvpn vtun0 server max-connections 30
    #         set interfaces openvpn vtun0 server topology subnet
    #         set interfaces openvpn vtun0 tls ca-certificate ca-1
    #         set interfaces openvpn vtun0 tls certificate srv-1
    #         set interfaces openvpn vtun0 tls dh-params dh-1
    #         set interfaces openvpn vtun0 server subnet 10.100.1.0/24
    #         commit
    #         exit
    #     '

    log "Starting KnockPort"
    log docker exec port-knock-server vbash -c \
        'cd /app && ~/venv/bin/python src/server.py -c tests/config.test.yaml --routing-type vyos --http-port '${KNOCKPORT_PORT_HTTP}' --https-port '${KNOCKPORT_PORT_HTTPS}' --cert tests/knock-port.testing.pem --key tests/knock-port.testing.key > tests/run_docker_tests.server.vyos.log 2>&1 &'
    docker exec port-knock-server vbash -c \
        'cd /app && ~/venv/bin/python src/server.py -c tests/config.test.yaml --routing-type vyos --http-port '${KNOCKPORT_PORT_HTTP}' --https-port '${KNOCKPORT_PORT_HTTPS}' --cert tests/knock-port.testing.pem --key tests/knock-port.testing.key > tests/run_docker_tests.server.vyos.log 2>&1 &'
    sleep 3


    # Run the tests
    run_command python ${BASE_DIR_PATH}/tests/tests.py

    run_command docker stop -t 1 port-knock-server
    run_command docker stop -t 1 port-knock-server-backend

fi
