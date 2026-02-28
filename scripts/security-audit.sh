#!/bin/bash
# Mobium Security Audit Script
# Run periodically or on-demand to check system security posture

echo "=== Mobium Security Audit ==="
echo "Date: $(date -u)"
echo ""

# --- Firewall ---
echo "🔥 FIREWALL"
sudo ufw status | grep -E "Status|ALLOW|DENY"
echo ""

# --- Fail2ban ---
echo "🚫 FAIL2BAN"
for jail in $(sudo fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*:\s*//;s/,//g'); do
    echo "  Jail: $jail"
    sudo fail2ban-client status "$jail" 2>/dev/null | grep -E "Currently|Total"
done
echo ""

# --- Open ports ---
echo "🔌 LISTENING PORTS"
ss -tlnp | grep LISTEN | awk '{printf "  %-6s %s\n", $4, $6}'
echo ""

# --- SSH config ---
echo "🔑 SSH"
echo "  Root login: $(grep -E '^PermitRootLogin' /etc/ssh/sshd_config | awk '{print $2}')"
echo "  Max auth tries: $(grep -E '^MaxAuthTries' /etc/ssh/sshd_config | awk '{print $2}')"
echo "  Password auth: $(grep -E '^PasswordAuthentication' /etc/ssh/sshd_config | awk '{print $2}')"
echo ""

# --- Active connections ---
echo "🌐 ACTIVE CONNECTIONS"
echo "  HTTP:  $(ss -tn state established '( sport = :80 )' | tail -n +2 | wc -l)"
echo "  HTTPS: $(ss -tn state established '( sport = :443 )' | tail -n +2 | wc -l)"
echo "  WS:    $(ss -tn state established '( sport = :8443 )' | tail -n +2 | wc -l)"
echo "  SSH:   $(ss -tn state established '( sport = :22 )' | tail -n +2 | wc -l)"
echo ""

# --- Service status ---
echo "⚙️  SERVICES"
for svc in nginx redis-server postgresql fail2ban ssh; do
    STATUS=$(systemctl is-active "$svc" 2>/dev/null)
    printf "  %-20s %s\n" "$svc" "$STATUS"
done
PM2_STATUS=$(pm2 jlist 2>/dev/null | python3 -c "
import sys,json
try:
    for p in json.load(sys.stdin):
        if p['name']=='mobium-server':
            s=p['pm2_env']
            print(f\"online (restarts: {s['restart_time']}, mem: {p['monit']['memory']//1048576}MB)\")
except: print('unknown')
" 2>/dev/null)
printf "  %-20s %s\n" "mobium-server" "$PM2_STATUS"
echo ""

# --- Disk encryption ---
echo "💾 STORAGE"
echo "  SD card: $(df -h / | tail -1 | awk '{print $5, "used of", $2}')"
echo "  SSD:     $(df -h /mnt/ssd | tail -1 | awk '{print $5, "used of", $2}')"
echo ""

# --- Recent auth failures ---
echo "🔍 RECENT AUTH FAILURES (last 24h)"
sudo journalctl -u ssh --since "24 hours ago" --no-pager 2>/dev/null | grep -c "Failed password" | xargs -I{} echo "  SSH failed passwords: {}"
echo ""

# --- Suspicious nginx access ---
echo "🕵️  SUSPICIOUS REQUESTS (last 24h)"
if [ -f /var/log/nginx/mobium-access.log ]; then
    echo "  4xx errors: $(grep -c ' 4[0-9][0-9] ' /var/log/nginx/mobium-access.log 2>/dev/null || echo 0)"
    echo "  5xx errors: $(grep -c ' 5[0-9][0-9] ' /var/log/nginx/mobium-access.log 2>/dev/null || echo 0)"
    echo "  Bot probes: $(grep -ciE 'wp-login|phpmyadmin|xmlrpc|\.env|\.git' /var/log/nginx/mobium-access.log 2>/dev/null || echo 0)"
fi
echo ""

# --- Updates ---
echo "📦 PENDING UPDATES"
UPDATES=$(apt list --upgradable 2>/dev/null | tail -n +2 | wc -l)
SECURITY=$(apt list --upgradable 2>/dev/null | grep -c security || echo 0)
echo "  Total: $UPDATES ($SECURITY security)"
echo ""

echo "=== Audit Complete ==="
