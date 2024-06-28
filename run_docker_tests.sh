#!/bin/bash

# Build the Docker image
docker build -t port-knock-server .

# Run the server in a Docker container
docker run -d --name port-knock-server -p 8080:8080 port-knock-server

# Wait for the server to start
sleep 5

# Install the docker Python library
pip install docker

# Run the tests
python test_server.py

# Stop and remove the Docker container
docker stop port-knock-server
docker rm port-knock-server
