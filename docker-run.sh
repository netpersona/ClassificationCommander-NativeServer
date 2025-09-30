#!/bin/bash

# Classification Commander - Docker Run Script

echo "Starting Classification Commander with Docker..."

# Check if .env exists
if [ ! -f .env ]; then
    echo "WARNING: .env file not found. Using default values."
    echo "For production, copy .env.example to .env and configure your secrets."
fi

# Build and run with docker-compose
docker-compose up --build -d

echo ""
echo "Classification Commander is starting..."
echo "Access the web interface at: http://localhost:5000"
echo ""
echo "To view logs: docker-compose logs -f"
echo "To stop: docker-compose down"
