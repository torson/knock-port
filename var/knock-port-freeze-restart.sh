#!/bin/bash

# Sending request and checking if log file timestamp is older than TTL.
# In such case it's considered that the service got stuck so we restart it

LOGFILE_PATH=/var/log/knock-port.log
TTL=10

log() {
    echo -e "--> $(date) : $1"
}

echo
log "Sending HTTP request"
curl -s -m 1 -d 'app=app1&access_key=test-ping' http://127.0.0.1/phase-1
log "sleep 5"
sleep 5

FILE_TIMESTAMP=$(stat -c %Y ${LOGFILE_PATH})
CURRENT_UNIXTIME=$(date +%s)
DIFF=$((CURRENT_UNIXTIME-FILE_TIMESTAMP))
if [[ "${DIFF}" -gt "${TTL}" ]]; then
    log "File ${LOGFILE_PATH} is older than ${TTL} : ${DIFF} s"
    log "/usr/sbin/service knock-port restart"
    /usr/sbin/service knock-port restart
else
    log "OK. File ${LOGFILE_PATH} is less than ${TTL}s old : ${DIFF}s"
fi
