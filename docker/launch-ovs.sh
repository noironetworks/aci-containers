#!/bin/sh

set -e
set -x

OVSCTL=/usr/share/openvswitch/scripts/ovs-ctl
VSCTL=/usr/bin/ovs-vsctl

${OVSCTL} start --system-id=c243acb9-0b18-4c63-a8c4-35a7e4fde79a

# Create OVS bridges if needed
for i in br-int br-access; do
    if ! ${VSCTL} br-exists ${i}; then
	${VSCTL} add-br ${i}
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

tail -n100 -f \
     /var/log/openvswitch/ovsdb-server.log \
     /var/log/openvswitch/ovs-vswitchd.log
