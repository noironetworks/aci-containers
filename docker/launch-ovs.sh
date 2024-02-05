#!/bin/sh

set -e
set -x

OVSCTL=/usr/share/openvswitch/scripts/ovs-ctl
VSCTL=/usr/bin/ovs-vsctl
SYS_ID=c243acb9-0b18-4c63-a8c4-35a7e4fde79a

echo "$(date) Starting OVS"
# Start OVS
${OVSCTL} start --system-id=${SYS_ID}
${VSCTL} set Open_vSwitch . other_config:hw-offload=true
${OVSCTL} restart --system-id=${SYS_ID}

# Cleanup
if ovs-vsctl show | grep "No such device"; then
    echo "$(date) Found Stale devices, cleaning up"
    ${OVSCTL} stop
    rm $PREFIX/etc/openvswitch/conf.db
    rm $PREFIX/var/lib/opflex-agent-ovs/endpoints/*.ep
    ${OVSCTL} start --system-id=${SYS_ID}
fi

echo "$(date) Creating bridges"
# Create OVS bridges if needed
dpid=0
for i in br-int br-access; do
    dpid=$((dpid+1))
    if ! ${VSCTL} br-exists ${i}; then
	${VSCTL} add-br ${i} -- set-fail-mode ${i} secure \
	    -- set bridge ${i} \
	    other-config:datapath-id=000000000000000$dpid \
	    other-config:mac-table-size="${OVS_MAC_TABLE_SIZE:=50000}"
    fi
done

echo "$(date) Resync host agent"
# Signal the host agent to resync OVS port configuration
ovsresync /usr/local/var/run/aci-containers-ep-rpc.sock

echo "$(date) Restart opflex agent"
# create this dir if opflex agent has not started yet
mkdir -p /usr/local/var/lib/opflex-agent-ovs/reboot-conf.d
# Signal the opflex-agent to reload
echo $(date) >> /usr/local/var/lib/opflex-agent-ovs/reboot-conf.d/reboot.conf

cat <<EOF > /etc/logrotate.conf
include /etc/logrotate.d
EOF

cat <<'EOF' > /etc/logrotate.d/openvswitch
/var/log/openvswitch/*.log {
    size 100k
    compress
    create 644 root root
    delaycompress
    missingok
    rotate 3
    nodateext
    postrotate
    # Tell Open vSwitch daemons to reopen their log files
    if [ -d /var/run/openvswitch ]; then
        for pidfile in `cd /var/run/openvswitch && echo *.pid`; do
            ovs-appctl -t "${pidfile%%.pid}" vlog/reopen
        done
    fi
    endscript
}
EOF

run_logrotate() {
    set +x
    while true; do
	sleep 60
	logrotate /etc/logrotate.conf
    done
}

run_logrotate &

tail -n+1 -F \
     /var/log/openvswitch/ovsdb-server.log \
     /var/log/openvswitch/ovs-vswitchd.log
