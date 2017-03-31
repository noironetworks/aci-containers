#!/bin/sh

set -e
set -x

OVSCTL=/usr/share/openvswitch/scripts/ovs-ctl
VSCTL=/usr/bin/ovs-vsctl
OVS_DB_LOG=/var/log/openvswitch/ovsdb-server.log
OVS_VSWITCHD_LOG=/var/log/openvswitch/ovs-vswitchd.log
SYS_ID=c243acb9-0b18-4c63-a8c4-35a7e4fde79a

# Start OVS
${OVSCTL} start --system-id=${SYS_ID}

# Create OVS bridges if needed
for i in br-int br-access; do
    if ! ${VSCTL} br-exists ${i}; then
	${VSCTL} add-br ${i} -- set-fail-mode ${i} secure
    fi
done

# Add uplink interfaces if needed
if ! ${VSCTL} iface-to-br ${ACI_UPLINK_IFACE}; then
    ${VSCTL} add-port br-int ${ACI_UPLINK_IFACE}
fi
if [[ ${ACI_ENCAP_TYPE} = "vxlan" ]]; then
    if ! ${VSCTL} iface-to-br br-int_vxlan0; then
	${VSCTL} add-port br-int br-int_vxlan0 -- \
		 set Interface br-int_vxlan0 type=vxlan \
		 options:remote_ip=flow options:key=flow options:dst_port=8472
    fi
fi

# Signal the host agent to resync OVS port configuration
ovsresync /usr/local/var/run/aci-containers-ep-rpc.sock

cat <<EOF > /etc/logrotate.conf
include /etc/logrotate.d
EOF

cat <<EOF > /etc/logrotate.d/openvswitch
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
    while true; do
	sleep 60
	logrotate /etc/logrotate.conf
    done
}

run_logrotate &

tail -n+1 -F \
     /var/log/openvswitch/ovsdb-server.log \
     /var/log/openvswitch/ovs-vswitchd.log
