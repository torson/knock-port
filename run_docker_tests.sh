#!/bin/bash

log() {
    echo -e "\n--> $(date) : $1"
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

# Build the Docker image
run_command docker build -t port-knock-server .

# Stop and remove the Docker container
run_command docker stop port-knock-server
run_command docker rm port-knock-server

# Run the server in a Docker container using host network
run_command docker run -d --cap-add=NET_ADMIN -v $(pwd):/app -p 8080:8080 --name port-knock-server port-knock-server

exit

# Wait for the server to start
run_command sleep 10

run_command pip install -r requirements.txt

# Run the tests
run_command python test_server.py

# Print container logs for debugging
run_command docker logs port-knock-server


# Stop and remove the Docker container
run_command docker stop port-knock-server
run_command docker rm port-knock-server
