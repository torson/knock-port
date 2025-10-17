#!/bin/sh

# script to trigger KnockPort

SERVER_IP=1.2.3.4

echo "Sending HTTP request"
curl -m 1 -d 'app=test_service_local&access_key=test_secret_http' http://${SERVER_IP}/step-1

echo "Sending HTTPS request"
curl -m 1 -d 'app=test_service_local&access_key=test_secret_https' -k https://${SERVER_IP}/step-2
