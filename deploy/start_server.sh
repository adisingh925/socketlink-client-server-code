#!/usr/bin/env bash
# start_server.sh — (re)start the standalone server on the VM, detached.
# Detaching matters: a plain `cmd &` over ssh keeps the ssh channel open until
# the child's stdout/stderr close, so the ssh call appears to hang.
cd /opt/socketlink || exit 1

pkill -f '/root/socketlink' 2>/dev/null
sleep 1

ulimit -n 1048576
setsid nohup /root/socketlink > /opt/socketlink/server.log 2>&1 < /dev/null &
sleep 3

echo "--- startup log:"
head -14 /opt/socketlink/server.log
echo "--- listening:"
ss -tln | grep -c ':8080' | sed 's/^/  sockets on 8080: /'
echo "--- ping: $(curl -s -m 5 localhost:8080/api/v1/ping)"
PID=$(pgrep -f '/root/socketlink' | head -1)
echo "--- pid $PID fd limit: $(grep 'Max open files' /proc/$PID/limits | awk '{print $4}')"
