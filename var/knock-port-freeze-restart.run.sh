#!/bin/bash

set -e

# This is a wrapper around the base script so the whole output (stdout and stderr)
# goes into a logfile and to stdout .

# output to logfile only or also to stdout
OUTPUT_TO_STDOUT_AND_LOGFILE=false

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

SCRIPT=$(echo $SCRIPT_PATH | sed 's/\.run\././')
LOG_FILE_PATH=/var/log/$(basename ${SCRIPT_PATH}).log

# checking for logdir existence
if [ ! -d $(dirname ${LOG_FILE_PATH}) ]; then
    mkdir -p $(dirname ${LOG_FILE_PATH})
fi

if [ "${OUTPUT_TO_STDOUT_AND_LOGFILE}" = "true" ]; then
    bash ${SCRIPT} $@ 2>&1 | tee -a ${LOG_FILE_PATH}
    FIRST_COMMAND_STATUS=${PIPESTATUS[0]}
    if [ "${FIRST_COMMAND_STATUS}" != "0" ]; then
        echo "ERROR! app exited with error.. "
        exit 1
    fi
else
    bash ${SCRIPT} $@ >> ${LOG_FILE_PATH} 2>&1
fi
