#!/bin/bash
python -m http.server $1 --bind 0.0.0.0 &
echo $! > /tmp/http_server.pid
