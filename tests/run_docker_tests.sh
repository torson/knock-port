#!/bin/bash

log() {
    echo -e "\n--> $(date) : $@"
}

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

VERBOSE=true
RUN_TESTS_ROUTING_TYPE_IPTABLES=true
RUN_TESTS_ROUTING_TYPE_NFTABLES=true
RUN_TESTS_ROUTING_TYPE_VYOS=false


if [ ! -f knock-port.testing.pem ] ; then
    log "generating testing certificate"
    echo "


    Testing

    knock-port.testing

    " | openssl req -x509 -newkey rsa:4096 -keyout knock-port.testing.key -out knock-port.testing.pem -days 3650 -nodes
fi

# Get the test_app port from config.test.yaml
TEST_SERVICE_PORT=$(grep port config.test.yaml | awk '{print $2}')
KNOCKPORT_PORT_HTTP=8080
KNOCKPORT_PORT_HTTPS=8443

CWD=$(pwd)
cd ..

if [[ "${RUN_TESTS_ROUTING_TYPE_IPTABLES}"  = "true" || "${RUN_TESTS_ROUTING_TYPE_NFTABLES}"  = "true" ]]; then
    # Build the Docker image
    run_command docker build -f tests/Dockerfile -t port-knock-server .
fi


### 1. iptables
if [[ "${RUN_TESTS_ROUTING_TYPE_IPTABLES}"  = "true" ]]; then
    log "### testing --routing-type iptables"

    # Stop and remove the Docker container
    docker stop -t 1 port-knock-server
    sleep 1
    # Run the server in a Docker container using host network
    run_command docker run --rm -d --cap-add=NET_ADMIN -v $(pwd):/app -p ${KNOCKPORT_PORT_HTTP}:${KNOCKPORT_PORT_HTTP} -p ${KNOCKPORT_PORT_HTTPS}:${KNOCKPORT_PORT_HTTPS} -p ${TEST_SERVICE_PORT}:${TEST_SERVICE_PORT} --name port-knock-server port-knock-server python -m http.server ${TEST_SERVICE_PORT}

    SERVICE_CONTAINER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' port-knock-server)

    log "installing requirements"
    log "docker exec port-knock-server bash -c \
        'pip install --no-cache-dir -r requirements.txt'"
    docker exec port-knock-server bash -c \
        'pip install --no-cache-dir -r requirements.txt'

    log "Drop access to the testing service port"
    run_command docker exec port-knock-server iptables -A INPUT -p tcp --dport ${TEST_SERVICE_PORT} -j DROP

    # python src/server.py -c tests/config.test.yaml --routing-type iptables --http-port ${KNOCKPORT_PORT_HTTP} --https-port ${KNOCKPORT_PORT_HTTPS} --cert tests/knock-port.testing.pem --key tests/knock-port.testing.key
    log docker exec port-knock-server bash -c \
        'python src/server.py -c tests/config.test.yaml --routing-type iptables --http-port '${KNOCKPORT_PORT_HTTP}' --https-port '${KNOCKPORT_PORT_HTTPS}' --cert tests/knock-port.testing.pem --key tests/knock-port.testing.key > tests/run_docker_tests.server.iptables.log 2>&1 &'
    docker exec port-knock-server bash -c \
        'python src/server.py -c tests/config.test.yaml --routing-type iptables --http-port '${KNOCKPORT_PORT_HTTP}' --https-port '${KNOCKPORT_PORT_HTTPS}' --cert tests/knock-port.testing.pem --key tests/knock-port.testing.key > tests/run_docker_tests.server.iptables.log 2>&1 &'
    sleep 3

    # Run the tests
    cd ${CWD}
    run_command python tests.py
    cd ..

    run_command docker stop -t 1 port-knock-server
fi

### 2. nftables
if [[ "${RUN_TESTS_ROUTING_TYPE_NFTABLES}"  = "true" ]]; then
    log "### testing --routing-type nftables"

    # Stop and remove the Docker container
    docker stop -t 1 port-knock-server
    sleep 1
    # Run the server in a Docker container using host network
    run_command docker run --rm -d --cap-add=NET_ADMIN -v $(pwd):/app -p ${KNOCKPORT_PORT_HTTP}:${KNOCKPORT_PORT_HTTP} -p ${KNOCKPORT_PORT_HTTPS}:${KNOCKPORT_PORT_HTTPS} -p ${TEST_SERVICE_PORT}:${TEST_SERVICE_PORT} --name port-knock-server port-knock-server python -m http.server ${TEST_SERVICE_PORT}

    SERVICE_CONTAINER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' port-knock-server)

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

    #   Docs:
    #     https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/getting-started-with-nftables_configuring-and-managing-networking
    #     https://unix.stackexchange.com/questions/753858/nftables-deleting-a-rule-without-passing-handle-similar-to-iptables-delete
    log docker exec port-knock-server bash -c \
        'python src/server.py -c tests/config.test.yaml --routing-type nftables --nftables-table filter --nftables-chain INPUT --http-port '${KNOCKPORT_PORT_HTTP}' --https-port '${KNOCKPORT_PORT_HTTPS}' --cert tests/knock-port.testing.pem --key tests/knock-port.testing.key > tests/run_docker_tests.server.nftables.log 2>&1 &'
    docker exec port-knock-server bash -c \
        'python src/server.py -c tests/config.test.yaml --routing-type nftables --nftables-table filter --nftables-chain INPUT --http-port '${KNOCKPORT_PORT_HTTP}' --https-port '${KNOCKPORT_PORT_HTTPS}' --cert tests/knock-port.testing.pem --key tests/knock-port.testing.key > tests/run_docker_tests.server.nftables.log 2>&1 &'
    sleep 3

    # Run the tests
    cd ${CWD}
    run_command python tests.py
    cd ..

    run_command docker stop -t 1 port-knock-server
fi


### 3. vyos
if [[ "${RUN_TESTS_ROUTING_TYPE_VYOS}"  = "true" ]]; then
    log "### testing --routing-type vyos"

    export VYOS_ROLLING_VERSION=1.5-rolling-202405260021
    bash create_vyos_docker_image.sh

    if [[ -z "${SERVICE_CONTAINER_IP}" ]]; then
        log "Starting backend service container"
        docker stop -t 1 port-knock-server
        run_command docker run -d --rm -v $(pwd):/app --name port-knock-server port-knock-server python -m http.server ${TEST_SERVICE_PORT}
        SERVICE_CONTAINER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' port-knock-server)
    fi

    if ! docker ps | grep vyos; then
        # docker run -d --rm --name vyos --privileged -v /lib/modules:/lib/modules -p ${TEST_SERVICE_PORT}:${TEST_SERVICE_PORT} vyos:${VYOS_ROLLING_VERSION} /sbin/init
        run_command docker run --rm -d --cap-add=NET_ADMIN -v $(pwd):/app -v /lib/modules:/lib/modules -p ${KNOCKPORT_PORT_HTTP}:${KNOCKPORT_PORT_HTTP} -p ${KNOCKPORT_PORT_HTTPS}:${KNOCKPORT_PORT_HTTPS} -p ${TEST_SERVICE_PORT}:${TEST_SERVICE_PORT} --name vyos vyos:${VYOS_ROLLING_VERSION} /sbin/init

    fi
    # docker exec -ti vyos su - vyos

    # set firewall ipv4 name IN-KnockPort default-action 'accept'
    # set firewall ipv4 input filter rule 20 action jump
    # set firewall ipv4 input filter rule 20 jump-target IN-KnockPort


    log docker exec port-knock-server bash -c \
        'python src/server.py -c tests/config.test.yaml --routing-type vyos --nftables-table vyos_filter --nftables-chain IN-KnockPort --port '${KNOCKPORT_PORT_HTTP}' > tests/run_docker_tests.server.vyos.log 2>&1 &'
    docker exec port-knock-server bash -c \
        'python src/server.py -c tests/config.test.yaml --routing-type vyos --nftables-table vyos_filter --nftables-chain IN-KnockPort --port '${KNOCKPORT_PORT_HTTP}' > tests/run_docker_tests.server.vyos.log 2>&1 &'
    sleep 3

    run_command docker stop -t 1 port-knock-server
    # run_command docker stop -t 1 vyos

fi
