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

if [ ! -f knock-port.testing.pem ] ; then
    log "generating testing certificate"
    echo "


    Testing

    knock-port.testing

    " | openssl req -x509 -newkey rsa:1024 -keyout knock-port.testing.key -out knock-port.testing.pem -days 3650 -nodes
fi

# Build the Docker image
CWD=$(pwd)
cd ..
run_command docker build -f tests/Dockerfile -t port-knock-server .

# Stop and remove the Docker container
docker stop -t 1 port-knock-server
docker rm port-knock-server

# Get the test_app port from config.test.yaml
TEST_SERVICE_PORT=$(grep port tests/config.test.yaml | awk '{print $2}')
KNOCKPORT_PORT=8080

# Run the server in a Docker container using host network
run_command docker run -d --cap-add=NET_ADMIN -v $(pwd):/app -p ${KNOCKPORT_PORT}:${KNOCKPORT_PORT} -p ${TEST_SERVICE_PORT}:${TEST_SERVICE_PORT} --name port-knock-server port-knock-server python -m http.server ${TEST_SERVICE_PORT}
cd ${CWD}

### installing requirements
log "docker exec port-knock-server bash -c \
    'pip install --no-cache-dir -r requirements.txt'"
docker exec port-knock-server bash -c \
    'pip install --no-cache-dir -r requirements.txt'

### testing --routing-type iptables
# Add a default drop rule for the test_app port
log docker exec port-knock-server bash -c \
    'python src/server.py -c tests/config.test.yaml --routing-type iptables --port '${KNOCKPORT_PORT}' > tests/run_docker_tests.server.iptables.log 2>&1 &'
docker exec port-knock-server bash -c \
    'python src/server.py -c tests/config.test.yaml --routing-type iptables --port '${KNOCKPORT_PORT}' > tests/run_docker_tests.server.iptables.log 2>&1 &'
sleep 3

# drop access to the testing service port
run_command docker exec port-knock-server iptables -A INPUT -p tcp --dport ${TEST_SERVICE_PORT} -j DROP

# drop outgoing traffic from knockport on HTTP port , allow only packets for initial handshake so Flask is able to handle the request . Client/curl will not receive a request on HTTP port
# run_command docker exec port-knock-server iptables -A OUTPUT -p tcp --sport ${KNOCKPORT_PORT} --tcp-flags ALL SYN,ACK -j ACCEPT
# run_command docker exec port-knock-server iptables -A OUTPUT -p tcp --sport ${KNOCKPORT_PORT} -j DROP

exit

# Run the tests
run_command python tests.py

# deleting iptables rule because it is set also as nftables rule
#     $ nft -a list ruleset
#     table ip filter { # handle 1
#         chain INPUT { # handle 1
#             type filter hook input priority filter; policy accept;
#             tcp dport 9999 counter packets 8 bytes 480 drop # handle 2
#         }
#     }

run_command docker exec port-knock-server \
    iptables -D INPUT -p tcp --dport ${TEST_SERVICE_PORT} -j DROP

log docker exec port-knock-server bash -c \
    'killall python'
docker exec port-knock-server bash -c \
    'killall python'

### testing --routing-type nftables
log docker exec port-knock-server bash -c \
    'python src/server.py -c tests/config.test.yaml --routing-type nftables --nftables-table filter --nftables-chain INPUT --port '${KNOCKPORT_PORT}' > tests/run_docker_tests.server.nftables.log 2>&1 &'
docker exec port-knock-server bash -c \
    'python src/server.py -c tests/config.test.yaml --routing-type nftables --nftables-table filter --nftables-chain INPUT --port '${KNOCKPORT_PORT}' > tests/run_docker_tests.server.nftables.log 2>&1 &'
sleep 3

# Create nftables table and chain
run_command docker exec port-knock-server \
    nft add table ip filter
log docker exec port-knock-server \
    nft add chain ip filter INPUT '{ type filter hook input priority filter; policy accept; }'
docker exec port-knock-server \
    nft add chain ip filter INPUT '{ type filter hook input priority filter; policy accept; }'
# setting default to drop
run_command docker exec port-knock-server \
    nft add rule ip filter INPUT tcp dport ${TEST_SERVICE_PORT} drop

# Run the tests
run_command python tests.py

log docker exec port-knock-server bash -c \
    'killall python'
docker exec port-knock-server bash -c \
    'killall python'

# Stop and remove the Docker container
run_command docker stop -t 1 port-knock-server
run_command docker rm port-knock-server
