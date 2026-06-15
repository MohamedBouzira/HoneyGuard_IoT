#!/bin/bash
# ================================================================
#  ENTRYPOINT — main-server
#  1. Clean null bytes from log files (leftover from previous runs)
#  2. writing custom cowrie database
#  3. Start supervisord
#  PFE 2025 — Mohamed Bouzira & Bakhti Rayane Abderaouef
# ================================================================


#1- cleaning:
echo "[entrypoint] Cleaning null bytes from log files..."
python3 -c "
import os
files = [
    '/var/log/mqtt/mqtt.json',
    '/var/log/http/http.json',
    '/var/log/coap/coap.json',
    '/var/log/tshark/packets.json',
    '/var/log/cowrie/cowrie.json',
    '/var/log/iot_platform/platform.json',
]
for f in files:
    if not os.path.exists(f): continue
    data = open(f,'rb').read()
    if b'\x00' not in data: continue
    clean = b'\n'.join(l for l in data.replace(b'\x00',b'').split(b'\n') if l.strip()) + b'\n'
    open(f,'wb').write(clean)
    print(f'[entrypoint] fixed null bytes in {f}')

# Clear packets.json — tshark format changed, old content is stale
pkt = '/var/log/tshark/packets.json'
if os.path.exists(pkt):
    open(pkt, 'w').close()
    print('[entrypoint] cleared stale packets.json')
"

#2- clean up stray .err/.out/.log files (supervisord routes everything to /dev/null)
echo "[entrypoint] Removing stray supervisor/cowrie log files..."
find /var/log -type f \( -name "*.err" -o -name "*.out" -o -name "*.log" -o -name "supervisor.log" \) \
    ! -name "cowrie.json" -delete 2>/dev/null || true
# also clean cowrie internal log dir
rm -f /home/cowrie/cowrie/var/log/cowrie.log 2>/dev/null || true

#user cowrie database:
echo "[*] Writing custom Cowrie userdb..."

cat > /home/cowrie/cowrie/etc/userdb.txt << 'EOF'
smarthome:1001:smarthome123
smarthome:1001:smarthome
smarthome:1001:password
smarthome:1001:admin123
smarthome:1001:1234
smarthome:1001:12345

root:0:toor
root:0:root123
root:0:admin
root:0:raspberry
root:0:ubnt
root:0:1234

admin:0:admin
admin:0:admin123
admin:0:1234
admin:0:password
admin:0:smarthome
pi:0:raspberry
pi:0:pi
user:1001:user
guest:1001:guest
support:1001:support
EOF

#3-starting supervisord:
echo "[entrypoint] Starting supervisord..."
exec /usr/bin/supervisord -n -c /etc/supervisor/conf.d/supervisord.conf

