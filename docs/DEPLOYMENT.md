# Deployment Guide

## Raspberry Pi 5 Setup

### Hardware Requirements

- Raspberry Pi 5 (4GB RAM recommended)
- 32GB+ microSD card
- Power supply
- Ethernet connection (recommended)

### OS Installation

1. **Install Raspberry Pi OS Lite (64-bit)**
   ```bash
   # Using Raspberry Pi Imager or flash manually
   # Download from: https://www.raspberrypi.com/software/
   ```

2. **Enable SSH** (optional)
   ```bash
   # Create empty ssh file in boot partition
   touch /boot/ssh
   ```

3. **Boot and configure**
   ```bash
   sudo raspi-config
   # Set hostname: securecomm
   # Enable auto-login (optional)
   ```

### Server Installation

1. **Install Docker**
   ```bash
   curl -fsSL https://get.docker.com -o get-docker.sh
   sudo sh get-docker.sh
   sudo usermod -aG docker $USER
   # Log out and back in
   ```

2. **Clone repository**
   ```bash
   git clone https://github.com/securecomm/securecomm.git
   cd securecomm
   ```

3. **Generate certificates**
   ```bash
   mkdir -p certs
   openssl req -x509 -newkey rsa:4096 \
     -keyout certs/key.pem \
     -out certs/cert.pem \
     -days 365 -nodes \
     -subj "/CN=securecomm.local"
   ```

4. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

5. **Start server**
   ```bash
   docker-compose up -d
   ```

6. **Verify**
   ```bash
   curl -k https://localhost:8443/health
   # Should return: OK
   ```

### Performance Tuning

For Pi5 with limited RAM:

```bash
# Edit docker-compose.yml
# Add resource limits:
services:
  server:
    deploy:
      resources:
        limits:
          memory: 256M
        reservations:
          memory: 128M
```

## Cloud Deployment

### VPS (DigitalOcean, AWS, etc.)

1. **Provision server** (Ubuntu 22.04 LTS)
   - 1 CPU
   - 1GB RAM minimum
   - 10GB storage

2. **Install dependencies**
   ```bash
   sudo apt update
   sudo apt install -y docker.io docker-compose
   ```

3. **Setup domain** (optional)
   ```bash
   # Point your domain to server IP
   # Let's Encrypt for TLS
   ```

4. **Deploy**
   ```bash
   # Copy project files
   scp -r securecomm/ user@server:/opt/
   ssh user@server
   cd /opt/securecomm
   
   # Use Let's Encrypt instead of self-signed
   # Install certbot and generate real certs
   
   docker-compose up -d
   ```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: securecomm-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: securecomm
  template:
    metadata:
      labels:
        app: securecomm
    spec:
      containers:
      - name: server
        image: securecomm/server:latest
        ports:
        - containerPort: 8443
        env:
        - name: SC_HOST
          value: "0.0.0.0"
        - name: SC_PORT
          value: "8443"
        volumeMounts:
        - name: data
          mountPath: /data
        - name: certs
          mountPath: /app/certs
          readOnly: true
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: securecomm-data
      - name: certs
        secret:
          secretName: securecomm-tls
```

## Reverse Proxy

### Caddy

```Caddyfile
securecomm.example.com {
    reverse_proxy localhost:8443
    tls {
        protocols tls1.3
    }
}
```

### Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name securecomm.example.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    ssl_protocols TLSv1.3;
    
    location / {
        proxy_pass http://localhost:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

## Backup

### Database Backup

```bash
# Automated backup script
#!/bin/bash
BACKUP_DIR=/backups/securecomm
DATE=$(date +%Y%m%d_%H%M%S)

# Stop server
docker-compose stop server

# Backup database
cp data/securecomm.db $BACKUP_DIR/securecomm_$DATE.db

# Restart server
docker-compose start server

# Keep only last 7 days
find $BACKUP_DIR -name "securecomm_*.db" -mtime +7 -delete
```

### Identity Backup

**Critical**: Users must backup their BIP39 mnemonic.

Server admin should backup:
- TLS certificates
- Database file
- Configuration files

## Monitoring

### Health Checks

```bash
# Systemd service for health monitoring
[Unit]
Description=SecureComm Health Check

[Service]
Type=oneshot
ExecStart=/usr/bin/curl -f -k https://localhost:8443/health || /usr/bin/systemctl restart securecomm
```

### Prometheus Metrics (Future)

```rust
// Server metrics endpoint
#[get("/metrics")]
async fn metrics() -> String {
    format!(
        "connected_users {}\n",
        state.connections.len()
    )
}
```

## Troubleshooting

### Server won't start

```bash
# Check logs
docker-compose logs -f server

# Verify database permissions
ls -la data/

# Test configuration
docker-compose config
```

### TLS errors

```bash
# Check certificate
curl -v -k https://localhost:8443

# Verify certificate format
openssl x509 -in certs/cert.pem -text -noout
```

### Connection refused

```bash
# Check if port is listening
sudo netstat -tlnp | grep 8443

# Check firewall
sudo ufw status
sudo iptables -L | grep 8443
```

## Security Hardening

1. **Firewall**: Only open necessary ports
   ```bash
   sudo ufw allow 443/tcp
   sudo ufw enable
   ```

2. **Fail2ban**: Protect against brute force
   ```bash
   sudo apt install fail2ban
   ```

3. **Updates**: Keep system updated
   ```bash
   sudo apt update && sudo apt upgrade -y
   docker-compose pull
   docker-compose up -d
   ```

4. **Non-root**: Run containers as non-root user
   ```yaml
   services:
     server:
       user: "1000:1000"
   ```