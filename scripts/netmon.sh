#!/bin/bash
# Mobium Network Monitor
# Runs periodically to log connection stats, detect anomalies, and alert

LOG_DIR="/mnt/ssd/data/mobium/logs"
mkdir -p "$LOG_DIR"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
LOG_FILE="$LOG_DIR/netmon-$(date +%Y-%m-%d).jsonl"

# --- Gather metrics ---

# Active connections to port 80/443/8443
CONN_80=$(ss -tn state established '( sport = :80 )' | tail -n +2 | wc -l)
CONN_443=$(ss -tn state established '( sport = :443 )' | tail -n +2 | wc -l)
CONN_8443=$(ss -tn state established '( sport = :8443 )' | tail -n +2 | wc -l)

# Unique IPs connected
UNIQUE_IPS=$(ss -tn state established '( sport = :80 or sport = :443 or sport = :8443 )' | \
    awk '{print $5}' | sed 's/:.*//' | sort -u | wc -l)

# Connections per IP (top offender)
TOP_IP=$(ss -tn state established '( sport = :80 or sport = :443 or sport = :8443 )' | \
    awk '{print $5}' | sed 's/:.*//' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')
TOP_IP_COUNT=$(ss -tn state established '( sport = :80 or sport = :443 or sport = :8443 )' | \
    awk '{print $5}' | sed 's/:.*//' | sort | uniq -c | sort -rn | head -1 | awk '{print $1}')

# Server health
HEALTH=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost/health)

# PM2 status
PM2_STATUS=$(pm2 jlist 2>/dev/null | python3 -c "
import sys, json
try:
    procs = json.load(sys.stdin)
    for p in procs:
        if p['name'] == 'mobium-server':
            print(json.dumps({
                'status': p['pm2_env']['status'],
                'uptime': p['pm2_env']['pm_uptime'],
                'restarts': p['pm2_env']['restart_time'],
                'memory': p['monit']['memory'],
                'cpu': p['monit']['cpu']
            }))
            break
except: print('{}')
" 2>/dev/null || echo '{}')

# System stats
LOAD=$(cat /proc/loadavg | awk '{print $1}')
MEM_USED=$(free -m | awk '/^Mem:/ {printf "%.0f", $3/$2*100}')
DISK_USED=$(df /mnt/ssd --output=pcent | tail -1 | tr -d ' %')

# fail2ban banned IPs
BANNED=$(sudo fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}')

# SYN flood detection
SYN_RECV=$(ss -tn state syn-recv | wc -l)

# --- Log entry ---
cat >> "$LOG_FILE" << ENTRY
{"ts":"$TIMESTAMP","conns":{"http":$CONN_80,"https":$CONN_443,"ws":$CONN_8443},"unique_ips":$UNIQUE_IPS,"top_ip":"${TOP_IP:-none}","top_ip_conns":${TOP_IP_COUNT:-0},"health":$HEALTH,"server":$PM2_STATUS,"system":{"load":$LOAD,"mem_pct":$MEM_USED,"disk_pct":$DISK_USED},"banned":${BANNED:-0},"syn_recv":$SYN_RECV}
ENTRY

# --- Alerts ---
ALERT=""

# Server down
if [ "$HEALTH" != "200" ]; then
    ALERT="$ALERT\n🔴 Server health check failed (HTTP $HEALTH)"
fi

# High connection count from single IP (possible DDoS)
if [ "${TOP_IP_COUNT:-0}" -gt 50 ]; then
    ALERT="$ALERT\n⚠️ High connection count from $TOP_IP ($TOP_IP_COUNT connections)"
fi

# SYN flood
if [ "$SYN_RECV" -gt 100 ]; then
    ALERT="$ALERT\n🔴 Possible SYN flood: $SYN_RECV half-open connections"
fi

# High load
if (( $(echo "$LOAD > 3.5" | bc -l 2>/dev/null || echo 0) )); then
    ALERT="$ALERT\n⚠️ High CPU load: $LOAD"
fi

# Disk filling up
if [ "$DISK_USED" -gt 85 ]; then
    ALERT="$ALERT\n⚠️ Disk usage at ${DISK_USED}%"
fi

# Output alert if any
if [ -n "$ALERT" ]; then
    echo -e "[$TIMESTAMP] ALERTS:$ALERT" >> "$LOG_DIR/alerts.log"
    echo -e "$ALERT"  # stdout for cron/pm2 capture
fi
