# Docker Deployment Guide

## Quick Start

### Using Docker Compose (Recommended)

1. **Copy environment variables**:
   ```bash
   cp .env.example .env
   ```

2. **Edit `.env` file** and set your secret key and credentials (optional)

3. **Run the application**:
   ```bash
   ./docker-run.sh
   ```
   
   Or manually:
   ```bash
   docker-compose up -d
   ```

4. **Access the application** at `http://localhost:5000`

### Using Docker Only

Build the image:
```bash
docker build -t classification-commander .
```

Run the container:
```bash
docker run -d \
  -p 5000:5000 \
  -v $(pwd)/config.json:/app/config.json \
  -v $(pwd)/credentials.json:/app/credentials.json \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/images:/app/images \
  -e SECRET_KEY=your-secret-key \
  --name classification-commander \
  classification-commander
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | Yes (production) | Secret key for session management |
| `ADMIN_USERNAME` | No | Admin username (overrides credentials.json) |
| `ADMIN_PASSWORD` | No | Admin password (overrides credentials.json) |
| `OPERATOR_USERNAME` | No | Operator username (overrides credentials.json) |
| `OPERATOR_PASSWORD` | No | Operator password (overrides credentials.json) |

## Volumes

The Docker setup mounts these directories:

- `./config.json` - Display configuration
- `./credentials.json` - User credentials (development)
- `./logs` - Application and audit logs
- `./images` - Uploaded display images

## Management Commands

**View logs**:
```bash
docker-compose logs -f
```

**Stop the application**:
```bash
docker-compose down
```

**Restart the application**:
```bash
docker-compose restart
```

**Rebuild and restart**:
```bash
docker-compose up -d --build
```

## Production Deployment

For production:

1. **Set a strong SECRET_KEY** in `.env`
2. **Use environment variables** for credentials instead of credentials.json
3. **Secure the host** - Use HTTPS reverse proxy (nginx, Traefik, etc.)
4. **Backup data** - Regularly backup config.json and logs
5. **Monitor logs** - Set up log aggregation for audit trails

### Example nginx reverse proxy config:

```nginx
server {
    listen 443 ssl;
    server_name classification.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Troubleshooting

**Container won't start**:
- Check logs: `docker-compose logs`
- Verify port 5000 is not in use: `netstat -tulpn | grep 5000`

**Permission errors**:
- Ensure volumes directories exist and are writable
- Check file ownership: `ls -la config.json credentials.json`

**Can't access web interface**:
- Verify container is running: `docker ps`
- Check port mapping: `docker port classification-commander`
- Test connection: `curl http://localhost:5000`
