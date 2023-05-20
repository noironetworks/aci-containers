#!/bin/sh

set -e
set -x
PREFIX=/usr/local
OVSCTL=$PREFIX/share/openvswitch/scripts/ovs-ctl
VSCTL=$PREFIX/bin/ovs-vsctl
SYS_ID=c243acb9-0b18-4c63-a8c4-35a7e4fde79a
export LD_LIBRARY_PATH=$PREFIX/lib:$LD_LIBRARY_PATH

# Start OVS
${OVSCTL} start --system-id=${SYS_ID}

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

# Signal the host agent to resync OVS port configuration
ovsresync $PREFIX/var/run/aci-containers-ep-rpc.sock

# create this dir if opflex agent has not started yet
mkdir -p $PREFIX/var/lib/opflex-agent-ovs/reboot-conf.d
# Signal the opflex-agent to reload
echo $(date) >> $PREFIX/var/lib/opflex-agent-ovs/reboot-conf.d/reboot.conf

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
    if [ -d $PREFIX/var/run/openvswitch ]; then
        for pidfile in `cd $PREFIX/var/run/openvswitch && echo *.pid`; do
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
     $PREFIX/var/log/openvswitch/ovsdb-server.log \
     $PREFIX/var/log/openvswitch/ovs-vswitchd.log
