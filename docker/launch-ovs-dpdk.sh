#!/bin/sh

set -e
set -x

OVSCTL=/usr/local/share/openvswitch/scripts/ovs-ctl
VSCTL=/usr/local/bin/ovs-vsctl
SYS_ID=c243acb9-0b18-4c63-a8c4-35a7e4fde79b

# Start OVS
${OVSCTL} start --system-id=${SYS_ID}

#Enable DPDK
${VSCTL} --no-wait set Open_vSwitch . other_config:dpdk-init=true
# ${VSCTL} --no-wait set Open_vSwitch . other_config:dpdk-extra="-d /usr/local/lib/librte_mempool_ring.so"
# ${VSCTL} --no-wait set Open_vSwitch . other_config:dpdk-socket-mem="1024,0"
# ${VSCTL} --no-wait set Open_vSwitch . other_config:pmd-cpu-mask=0x6

# Start OVS
${OVSCTL} stop --system-id=${SYS_ID}
${OVSCTL} start --system-id=${SYS_ID}

# Create OVS bridges if needed
dpid=0
for i in br-int br-access; do
    dpid=$((dpid+1))
    if ! ${VSCTL} br-exists ${i}; then
        ${VSCTL} add-br ${i} -- set-fail-mode ${i} secure \
            -- set bridge ${i} datapath_type=netdev \
            other-config:datapath-id=000000000000000$dpid \
            other-config:mac-table-size="${OVS_MAC_TABLE_SIZE:=50000}"
    fi
done

# create this dir if opflex agent has not started yet
mkdir -p /usr/local/var/lib/opflex-agent-ovs/reboot-conf.d
# Signal the opflex-agent to reload
echo $(date) >> /usr/local/var/lib/opflex-agent-ovs/reboot-conf.d/reboot.conf

cat <<EOF > /etc/logrotate.conf
include /etc/logrotate.d
EOF

cat <<'EOF' > /etc/logrotate.d/openvswitch
/usr/local/var/log/openvswitch/*.log {
    size 100k
    compress
    create 644 root root
    delaycompress
    missingok
    rotate 3
    nodateext
    postrotate
    # Tell Open vSwitch daemons to reopen their log files
    if [ -d /usr/local/var/run/openvswitch ]; then
        for pidfile in `cd /usr/local/var/run/openvswitch && echo *.pid`; do
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
     /usr/local/var/log/openvswitch/ovsdb-server.log \
     /usr/local/var/log/openvswitch/ovs-vswitchd.log
