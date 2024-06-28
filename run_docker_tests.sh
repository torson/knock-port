#!/bin/bash

# Build the Docker image
docker build -t port-knock-server .

# Stop and remove the Docker container
docker stop port-knock-server
docker rm port-knock-server

# Run the server in a Docker container
docker run -d -v $(pwd):/app --name port-knock-server -p 8080:8080 port-knock-server

# Wait for the server to start
sleep 5

pip install -r requirements.txt

# Run the tests
python test_server.py

# Print container logs for debugging
docker logs port-knock-server

# Don't exit immediately to keep the container running for manual inspection if needed
# exit

# Stop and remove the Docker container
docker stop port-knock-server
docker rm port-knock-server
