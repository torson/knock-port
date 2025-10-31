#!/bin/bash

# mamba create -n knockport python=3.12
# mamba activate knockport
# pip install -r requirements.txt

set -e

# by default all 3 firewall types are being tested (set to true)
# if any type envvar is already set to true then only those will be tested

## to enable specific firewall type and run this script
# RUN_TESTS_ROUTING_TYPE_IPTABLES=true tests/run_docker_tests.sh
# RUN_TESTS_ROUTING_TYPE_NFTABLES=true tests/run_docker_tests.sh
# RUN_TESTS_ROUTING_TYPE_VYOS=true tests/run_docker_tests.sh

if [[ -z ${RUN_TESTS_ROUTING_TYPE_IPTABLES} && -z ${RUN_TESTS_ROUTING_TYPE_NFTABLES} && -z ${RUN_TESTS_ROUTING_TYPE_VYOS}  ]]; then
    # none was set so we set all to true
    RUN_TESTS_ROUTING_TYPE_IPTABLES=true
    RUN_TESTS_ROUTING_TYPE_NFTABLES=true
    RUN_TESTS_ROUTING_TYPE_VYOS=true
fi

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

# make sure logs are writable by non-root user inside docker container
chmod 666 ${BASE_DIR_PATH}/tests/*.log
chmod 666 ${BASE_DIR_PATH}/cache/*.json

if [ ! -f ${BASE_DIR_PATH}/tests/knockport.testing.pem ] ; then
    log "generating testing certificate"
    echo "


    Testing

    knockport.testing

    " | openssl req -x509 -newkey rsa:4096 -keyout tests/knockport.testing.key -out tests/knockport.testing.pem -days 3650 -nodes
else
    log "${BASE_DIR_PATH}/tests/knockport.testing.pem already exists."
fi
chmod 666 ${BASE_DIR_PATH}/tests/knockport.testing.key ${BASE_DIR_PATH}/tests/knockport.testing.pem

if [ "${GENERATE_CERTIFICATE_ONLY}" = "true" ]; then
    exit
fi

cp ${BASE_DIR_PATH}/tests/config.test.tmpl.yaml ${BASE_DIR_PATH}/tests/config.test.yaml

# Get the test_app port from config.test.yaml
TEST_SERVICE_PORT_LOCAL=$(grep -v -P "^ *#" ${BASE_DIR_PATH}/tests/config.test.yaml | grep -A 5 test_service_local: | grep port: | awk '{print $2}')
TEST_SERVICE_PORT_NONLOCAL=$(grep -v -P "^ *#" ${BASE_DIR_PATH}/tests/config.test.yaml | grep -A 5 test_service_nonlocal: | grep port: | awk '{print $2}')
TEST_SERVICE_PORT_NONLOCAL_DESTINATION=$(grep -v -P "^ *#" ${BASE_DIR_PATH}/tests/config.test.yaml | grep -A 10 test_service_nonlocal: | grep destination: | awk '{print $2}' | awk -F: '{print $2}')

KNOCKPORT_PORT_HTTP=8080
KNOCKPORT_PORT_HTTPS=8443

# install app dependencies into the Python Docker image
run_command docker build -f tests/Dockerfile -t port-knock-server .

# starting backend server for testing forwarding rules - config test_service_nonlocal
if docker stop -t 1 port-knock-server-backend ; then
    sleep 2
fi
run_command docker run --rm -d --name port-knock-server-backend port-knock-server python -m http.server ${TEST_SERVICE_PORT_NONLOCAL_DESTINATION}
export BACKEND_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' port-knock-server-backend)

# generating tests/config.test.yaml
envsubst < ${BASE_DIR_PATH}/tests/config.test.tmpl.yaml > ${BASE_DIR_PATH}/tests/config.test.yaml

run_command pip install -r requirements.txt

### 1. iptables
if [[ "${RUN_TESTS_ROUTING_TYPE_IPTABLES}"  = "true" ]]; then
    log "### testing --firewall-type iptables"

    # Stop and remove the Docker container
    if docker stop -t 1 port-knock-server ; then
        sleep 2
    fi

    # Run the server in a Docker container using --privileged (to enable port forwarding, --cap-add=SYS_ADMIN is not enough) and --cap-add=NET_ADMIN (for running iptables commands) and starting a basic web server for testing local service
    run_command docker run --rm -d --privileged --cap-add=NET_ADMIN -v ${BASE_DIR_PATH}:/app -p ${KNOCKPORT_PORT_HTTP}:${KNOCKPORT_PORT_HTTP} -p ${KNOCKPORT_PORT_HTTPS}:${KNOCKPORT_PORT_HTTPS} -p ${TEST_SERVICE_PORT_LOCAL}:${TEST_SERVICE_PORT_LOCAL} -p ${TEST_SERVICE_PORT_NONLOCAL}:${TEST_SERVICE_PORT_NONLOCAL} --name port-knock-server port-knock-server python -m http.server ${TEST_SERVICE_PORT_LOCAL}

    log "installing requirements"
    log "docker exec port-knock-server bash -c \
        'pip install --no-cache-dir -r requirements.txt'"
    docker exec port-knock-server bash -c \
        'pip install --no-cache-dir -r requirements.txt'

    log "Enabling port-forwarding"
    log "docker exec -u root port-knock-server bash -c \
        'echo 1 > /proc/sys/net/ipv4/ip_forward'"
    docker exec -u root port-knock-server bash -c \
        'echo 1 > /proc/sys/net/ipv4/ip_forward'

    log "Starting KnockPort"
    log docker exec -u root port-knock-server bash -c \
        'python src/main.py --service-rule-cleanup-on-shutdown -c tests/config.test.yaml --firewall-type iptables --http-port '${KNOCKPORT_PORT_HTTP}' --https-port '${KNOCKPORT_PORT_HTTPS}' --cert tests/knockport.testing.pem --key tests/knockport.testing.key > tests/run_docker_tests.server.iptables.log 2>&1 &'
    docker exec -u root port-knock-server bash -c \
        'python src/main.py --service-rule-cleanup-on-shutdown -c tests/config.test.yaml --firewall-type iptables --http-port '${KNOCKPORT_PORT_HTTP}' --https-port '${KNOCKPORT_PORT_HTTPS}' --cert tests/knockport.testing.pem --key tests/knockport.testing.key > tests/run_docker_tests.server.iptables.log 2>&1 &'
    sleep 3

    # curl -m 1 -d 'app=test_service_local&access_key=test_secret_http' http://localhost:8080/step-1
    # # with 2FA token
    # curl -m 1 -d 'app=test_service_local&access_key=test_secret_http&token=' http://localhost:8080/step-1
    # curl -m 1 -d 'app=test_service_local&access_key=test_secret_https' https://localhost:8443/step-2 -k
    # curl -m 1 http://localhost:1194/

    # curl -m 1 -d 'app=test_service_nonlocal&access_key=test_secret_http' http://localhost:8080/step-1
    # curl -m 1 -d 'app=test_service_nonlocal&access_key=test_secret_https' https://localhost:8443/step-2 -k
    # curl -m 1 http://localhost:1294/


    # Run the tests , needs to be run from repo root
    run_command python tests/tests.py

    ###
    log "Running tests again with user knockport and --use-sudo argument"
    docker exec -u root port-knock-server bash -c 'pkill -f main.py' || true
    sleep 5

    log "Starting KnockPort"
    log docker exec -u knockport port-knock-server bash -c \
        'python src/main.py --service-rule-cleanup-on-shutdown -c tests/config.test.yaml --firewall-type iptables --http-port '${KNOCKPORT_PORT_HTTP}' --https-port '${KNOCKPORT_PORT_HTTPS}' --cert tests/knockport.testing.pem --key tests/knockport.testing.key --use-sudo > tests/run_docker_tests.server.iptables.log 2>&1 &'
    docker exec -u knockport port-knock-server bash -c \
        'python src/main.py --service-rule-cleanup-on-shutdown -c tests/config.test.yaml --firewall-type iptables --http-port '${KNOCKPORT_PORT_HTTP}' --https-port '${KNOCKPORT_PORT_HTTPS}' --cert tests/knockport.testing.pem --key tests/knockport.testing.key --use-sudo > tests/run_docker_tests.server.iptables.log 2>&1 &'

    sleep 3
    log "Running tests"
    run_command python tests/tests.py

    ###
    log "Running tests with --waf-http-port/--waf-https-port arguments"
    docker exec -u root port-knock-server bash -c 'pkill -f main.py' || true
    sleep 5

    log "Starting KnockPort with WAF ports"
    log docker exec -u root port-knock-server bash -c \
        'python src/main.py --service-rule-cleanup-on-shutdown -c tests/config.test.yaml --firewall-type iptables --http-port 8081 --https-port 8444 --waf-http-port '${KNOCKPORT_PORT_HTTP}' --waf-https-port '${KNOCKPORT_PORT_HTTPS}' --waf-trusted-ips 127.0.0.1 --cert tests/knockport.testing.pem --key tests/knockport.testing.key > tests/run_docker_tests.server.iptables.log 2>&1 &'
    docker exec -u root port-knock-server bash -c \
        'python src/main.py --service-rule-cleanup-on-shutdown -c tests/config.test.yaml --firewall-type iptables --http-port 8081 --https-port 8444 --waf-http-port '${KNOCKPORT_PORT_HTTP}' --waf-https-port '${KNOCKPORT_PORT_HTTPS}' --waf-trusted-ips 127.0.0.1 --cert tests/knockport.testing.pem --key tests/knockport.testing.key > tests/run_docker_tests.server.iptables.log 2>&1 &'

    sleep 3

    log "Starting Nginx reverse proxy"
    docker exec -u root port-knock-server bash -c \
        'nginx -c /app/tests/nginx-knockport.conf'

    sleep 3
    log "Running tests through Nginx"
    run_command python tests/tests.py

    # ###
    # ### integration tests fail with this, but should be tested once in a while
    # log "Running tests with different/incorrect --waf-trusted-ips IP"
    # docker exec -u root port-knock-server bash -c 'pkill -f main.py' || true
    # docker exec -u root port-knock-server bash -c 'pkill -f nginx' || true
    # sleep 5

    # log "Starting KnockPort with WAF ports"
    # log docker exec -u root port-knock-server bash -c \
    #     'python src/main.py -c tests/config.test.yaml --firewall-type iptables --http-port 8081 --https-port 8444 --waf-http-port '${KNOCKPORT_PORT_HTTP}' --waf-https-port '${KNOCKPORT_PORT_HTTPS}' --waf-trusted-ips 172.0.0.1 --cert tests/knockport.testing.pem --key tests/knockport.testing.key > tests/run_docker_tests.server.iptables.log 2>&1 &'
    # docker exec -u root port-knock-server bash -c \
    #     'python src/main.py -c tests/config.test.yaml --firewall-type iptables --http-port 8081 --https-port 8444 --waf-http-port '${KNOCKPORT_PORT_HTTP}' --waf-https-port '${KNOCKPORT_PORT_HTTPS}' --waf-trusted-ips 172.0.0.1 --cert tests/knockport.testing.pem --key tests/knockport.testing.key > tests/run_docker_tests.server.iptables.log 2>&1 &'

    # sleep 3

    # log "Starting Nginx reverse proxy"
    # docker exec -u root port-knock-server bash -c \
    #     'nginx -c /app/tests/nginx-knockport.conf'

    # sleep 3
    # log "Running tests through Nginx"
    # run_command python tests/tests.py

    run_command docker stop -t 1 port-knock-server
fi


### 2. nftables
if [[ "${RUN_TESTS_ROUTING_TYPE_NFTABLES}"  = "true" ]]; then
    log "### testing --firewall-type nftables"

    # Stop and remove the Docker container
    if docker stop -t 1 port-knock-server ; then
        sleep 2
    fi

    # Run the server in a Docker container using --privileged (to enable port forwarding, --cap-add=SYS_ADMIN is not enough) and --cap-add=NET_ADMIN (for running iptables commands)
    run_command docker run --rm -d --privileged --cap-add=NET_ADMIN -v ${BASE_DIR_PATH}:/app -p ${KNOCKPORT_PORT_HTTP}:${KNOCKPORT_PORT_HTTP} -p ${KNOCKPORT_PORT_HTTPS}:${KNOCKPORT_PORT_HTTPS} -p ${TEST_SERVICE_PORT_LOCAL}:${TEST_SERVICE_PORT_LOCAL} -p ${TEST_SERVICE_PORT_NONLOCAL}:${TEST_SERVICE_PORT_NONLOCAL} --name port-knock-server port-knock-server python -m http.server ${TEST_SERVICE_PORT_LOCAL}

    log "installing requirements"
    log "docker exec port-knock-server bash -c \
        'pip install --no-cache-dir -r requirements.txt'"
    docker exec port-knock-server bash -c \
        'pip install --no-cache-dir -r requirements.txt'

    log "Enabling port-forwarding"
    log "docker exec -u root port-knock-server bash -c \
        'echo 1 > /proc/sys/net/ipv4/ip_forward'"
    docker exec -u root port-knock-server bash -c \
        'echo 1 > /proc/sys/net/ipv4/ip_forward'

    #   Docs:
    #     https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/getting-started-with-nftables_configuring-and-managing-networking
    #     https://unix.stackexchange.com/questions/753858/nftables-deleting-a-rule-without-passing-handle-similar-to-iptables-delete
    log "Starting KnockPort"
    log docker exec -u root port-knock-server bash -c \
        'python src/main.py --service-rule-cleanup-on-shutdown -c tests/config.test.yaml --firewall-type nftables --http-port '${KNOCKPORT_PORT_HTTP}' --https-port '${KNOCKPORT_PORT_HTTPS}' --cert tests/knockport.testing.pem --key tests/knockport.testing.key > tests/run_docker_tests.server.nftables.log 2>&1 &'
    docker exec -u root port-knock-server bash -c \
        'python src/main.py --service-rule-cleanup-on-shutdown -c tests/config.test.yaml --firewall-type nftables --http-port '${KNOCKPORT_PORT_HTTP}' --https-port '${KNOCKPORT_PORT_HTTPS}' --cert tests/knockport.testing.pem --key tests/knockport.testing.key > tests/run_docker_tests.server.nftables.log 2>&1 &'

    sleep 3

    # Run the tests , needs to be run from repo root
    log "Running tests"
    run_command python tests/tests.py

    ###
    log "Running tests again with user knockport and --use-sudo argument"
    docker exec -u root port-knock-server bash -c 'pkill -f main.py' || true
    sleep 5

    log "Starting KnockPort"
    log docker exec -u knockport port-knock-server bash -c \
        'python src/main.py --service-rule-cleanup-on-shutdown -c tests/config.test.yaml --firewall-type nftables --http-port '${KNOCKPORT_PORT_HTTP}' --https-port '${KNOCKPORT_PORT_HTTPS}' --cert tests/knockport.testing.pem --key tests/knockport.testing.key --use-sudo > tests/run_docker_tests.server.nftables.log 2>&1 &'
    docker exec -u knockport port-knock-server bash -c \
        'python src/main.py --service-rule-cleanup-on-shutdown -c tests/config.test.yaml --firewall-type nftables --http-port '${KNOCKPORT_PORT_HTTP}' --https-port '${KNOCKPORT_PORT_HTTPS}' --cert tests/knockport.testing.pem --key tests/knockport.testing.key --use-sudo > tests/run_docker_tests.server.nftables.log 2>&1 &'

    sleep 3

    log "Running tests"
    run_command python tests/tests.py

    ###
    log "Running tests again with custom INPUT and FORWARD chains"
    docker exec -u root port-knock-server bash -c 'pkill -f main.py' || true
    sleep 5
    log "Starting KnockPort"
    log docker exec -u root port-knock-server bash -c \
        'python src/main.py --service-rule-cleanup-on-shutdown -c tests/config.test.yaml --firewall-type nftables --http-port '${KNOCKPORT_PORT_HTTP}' --https-port '${KNOCKPORT_PORT_HTTPS}' --cert tests/knockport.testing.pem --key tests/knockport.testing.key --nftables-chain-input IN-KnockPort --nftables-chain-forward FWD-KnockPort > tests/run_docker_tests.server.nftables.log 2>&1 &'
    docker exec -u root port-knock-server bash -c \
        'python src/main.py --service-rule-cleanup-on-shutdown -c tests/config.test.yaml --firewall-type nftables --http-port '${KNOCKPORT_PORT_HTTP}' --https-port '${KNOCKPORT_PORT_HTTPS}' --cert tests/knockport.testing.pem --key tests/knockport.testing.key --nftables-chain-input IN-KnockPort --nftables-chain-forward FWD-KnockPort > tests/run_docker_tests.server.nftables.log 2>&1 &'

    sleep 3

    log "Running tests"
    run_command python tests/tests.py

    run_command docker stop -t 1 port-knock-server
fi


### 3. vyos
if [[ "${RUN_TESTS_ROUTING_TYPE_VYOS}"  = "true" ]]; then
    log "### testing --firewall-type vyos"

    if [ -f ${BASE_DIR_PATH}/tests/.env ]; then
        source ${BASE_DIR_PATH}/tests/.env
    fi
    bash ${BASE_DIR_PATH}/tests/create_vyos_docker_image.sh || exit 1

    # install app dependencies into the VyOs Docker image
    run_command docker build -f tests/vyos.Dockerfile --build-arg VYOS_ROLLING_VERSION="${VYOS_ROLLING_VERSION}" -t vyos:${VYOS_ROLLING_VERSION}-extras .

    # Stop and remove the Docker container
    if docker stop -t 1 port-knock-server ; then
        # vyos container can take a few seconds to be stopped and removed
        sleep 5
    fi

    if ! docker ps | grep -P "port-knock-server$"; then
        # https://docs.vyos.io/en/latest/installation/virtual/docker.html
        run_command docker run --rm -d --privileged -v ${BASE_DIR_PATH}:/app -v /lib/modules:/lib/modules -p ${KNOCKPORT_PORT_HTTP}:${KNOCKPORT_PORT_HTTP} -p ${KNOCKPORT_PORT_HTTPS}:${KNOCKPORT_PORT_HTTPS} -p ${TEST_SERVICE_PORT_LOCAL}:${TEST_SERVICE_PORT_LOCAL} -p ${TEST_SERVICE_PORT_NONLOCAL}:${TEST_SERVICE_PORT_NONLOCAL} --name port-knock-server vyos:${VYOS_ROLLING_VERSION}-extras /sbin/init
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
            set system login user knockport authentication plaintext-password knockport
            commit
            exit
        '

    ## done in Dockerfile
    # docker exec port-knock-server bash -c '
    #         echo alias\ ll="ls\ -alF" >> ~/.bashrc
    #         echo "Installing python-pip3"
    #         echo "deb http://deb.debian.org/debian/ bookworm main contrib non-free non-free-firmware" > /etc/apt/sources.list
    #         apt-get update
    #         apt-get install -y python3-pip python3-venv
    #         python3 -m venv ~/venv
    #         echo "installing KnockPort requirements"
    #         cd /app
    #         ~/venv/bin/pip install --no-cache-dir -r requirements.txt
    #     '

    docker exec -u knockport port-knock-server bash -c '
            echo "installing KnockPort requirements"
            cd /app
            ~/venv/bin/pip install --no-cache-dir -r requirements.txt
            echo "Start testing web server for testing the service port"
            ~/venv/bin/python -m http.server '${TEST_SERVICE_PORT_LOCAL}' > tests/run_docker_tests.http-server.vyos.log 2>&1 &
        '

    log "Setting up shell environmnet"
    docker exec -u vyos port-knock-server vbash -c '
            echo alias\ ll="ls\ -alF" >> ~/.bashrc
        '
    docker exec -u knockport port-knock-server vbash -c '
            echo alias\ ll="ls\ -alF" >> ~/.bashrc
        '

    ## done in app
    # log "Drop access to the testing service port"
    # docker exec -u vyos port-knock-server vbash -c '
    #         echo alias\ ll="ls\ -alF" >> ~/.bashrc
    #         source /opt/vyatta/etc/functions/script-template
    #         configure
    #         echo "Create chain IN-KnockPort with default continue rule and drop rule for the service port"
    #         set firewall ipv4 name IN-KnockPort default-action continue
    #         set firewall ipv4 name IN-KnockPort rule 100 action drop
    #         set firewall ipv4 name IN-KnockPort rule 100 protocol tcp
    #         set firewall ipv4 name IN-KnockPort rule 100 destination port '${TEST_SERVICE_PORT_LOCAL}'
    #         set firewall ipv4 input filter rule 20 action jump
    #         set firewall ipv4 input filter rule 20 jump-target IN-KnockPort
    #         echo "Create chain FWD-KnockPort with default continue rule and drop rule for the service port"
    #         set firewall ipv4 name FWD-KnockPort default-action continue
    #         set firewall ipv4 name FWD-KnockPort rule 100 action drop
    #         set firewall ipv4 name FWD-KnockPort rule 100 protocol tcp
    #         set firewall ipv4 name FWD-KnockPort rule 100 destination port '${TEST_SERVICE_PORT_NONLOCAL}'
    #         set firewall ipv4 forward filter rule 20 action jump
    #         set firewall ipv4 forward filter rule 20 jump-target FWD-KnockPort
    #         commit
    #     '

    ## done in app
    # log "Create NAT chains by creating a dummy NAT rule and then removing it"
    #  docker exec -u vyos port-knock-server vbash -c '
    #          echo alias\ ll="ls\ -alF" >> ~/.bashrc
    #          source /opt/vyatta/etc/functions/script-template
    #          configure
    #          set nat destination rule 101 description 'blank-DNAT-rule'
    #          set nat destination rule 101 destination port '65535'
    #          set nat destination rule 101 inbound-interface name 'eth0'
    #          set nat destination rule 101 protocol 'tcp'
    #          set nat destination rule 101 translation address '10.255.255.254'
    #          set nat destination rule 101 translation port '65535'
    #          commit
    #          del nat destination rule 101
    #          commit
    #      '

    ## not needed for testing
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
    log docker exec -u root port-knock-server vbash -c \
        'cd /app && ~/venv/bin/python src/main.py --service-rule-cleanup-on-shutdown -c tests/config.test.yaml --firewall-type vyos --http-port '${KNOCKPORT_PORT_HTTP}' --https-port '${KNOCKPORT_PORT_HTTPS}' --cert tests/knockport.testing.pem --key tests/knockport.testing.key > tests/run_docker_tests.server.vyos.log 2>&1 &'

    docker exec -u root port-knock-server vbash -c \
        'cd /app && ~/venv/bin/python src/main.py --service-rule-cleanup-on-shutdown -c tests/config.test.yaml --firewall-type vyos --http-port '${KNOCKPORT_PORT_HTTP}' --https-port '${KNOCKPORT_PORT_HTTPS}' --cert tests/knockport.testing.pem --key tests/knockport.testing.key > tests/run_docker_tests.server.vyos.log 2>&1 &'
    # app init takes a bit longer on clean vyos as it creates firewall rules using the 'set' commands which are slow
    sleep 15

    # Run the tests , needs to be run from repo root
    run_command python tests/tests.py

    ###
    log "Running tests again with user knockport and --use-sudo argument"
    docker exec -u root port-knock-server bash -c 'pkill -f main.py' || true
    sleep 5

    log "Initializing firewall because we're later running KnockPort with --use-sudo so it doesn't have permission to run 'sudo -u vyos vbash'"
    docker exec -u vyos port-knock-server vbash -c '
            source /opt/vyatta/etc/functions/script-template
            configure
            echo "Initialize NAT table"
                set nat destination rule 101 description 'blank-DNAT-rule'
                set nat destination rule 101 destination port '65535'
                set nat destination rule 101 inbound-interface name 'eth0'
                set nat destination rule 101 protocol 'tcp'
                set nat destination rule 101 translation address '10.255.255.254'
                set nat destination rule 101 translation port '65535'
                commit
                del nat destination rule 101
                commit
            echo "Initialize filter chains"
                echo "Create chain IN-KnockPort with default continue rule"
                set firewall ipv4 name IN-KnockPort default-action continue
                set firewall ipv4 input filter rule 9999 action jump
                set firewall ipv4 input filter rule 9999 jump-target IN-KnockPort
                echo "Create chain FWD-KnockPort with default continue rule"
                set firewall ipv4 name FWD-KnockPort default-action continue
                set firewall ipv4 forward filter rule 9999 action jump
                set firewall ipv4 forward filter rule 9999 jump-target FWD-KnockPort
                commit
            exit
        '

    log "Starting KnockPort"
    log docker exec -u knockport port-knock-server vbash -c \
        'cd /app && ~/venv/bin/python src/main.py --service-rule-cleanup-on-shutdown -c tests/config.test.yaml --firewall-type vyos --http-port '${KNOCKPORT_PORT_HTTP}' --https-port '${KNOCKPORT_PORT_HTTPS}' --cert tests/knockport.testing.pem --key tests/knockport.testing.key --use-sudo > tests/run_docker_tests.server.vyos.log 2>&1 &'

    docker exec -u knockport port-knock-server vbash -c \
        'cd /app && ~/venv/bin/python src/main.py --service-rule-cleanup-on-shutdown -c tests/config.test.yaml --firewall-type vyos --http-port '${KNOCKPORT_PORT_HTTP}' --https-port '${KNOCKPORT_PORT_HTTPS}' --cert tests/knockport.testing.pem --key tests/knockport.testing.key --use-sudo > tests/run_docker_tests.server.vyos.log 2>&1 &'
    # app init takes a bit longer on clean vyos as it creates firewall rules using the 'set' commands which are slow
    sleep 15

    # Run the tests , needs to be run from repo root
    run_command python tests/tests.py

    run_command docker stop -t 1 port-knock-server
    run_command docker stop -t 1 port-knock-server-backend

fi
