#!/bin/sh

set -e
set -x

CNIBIN=/mnt/cni-bin/cni/bin
PREFIX=/usr/local
VARDIR=${PREFIX}/var
ACIBIN=${PREFIX}/bin
HOSTAGENT=${ACIBIN}/aci-containers-host-agent
HOSTAGENT_CONF=/usr/local/etc/aci-containers/host-agent.conf
KUBECONFIG=/usr/local/etc/kubeconfig

if [ -w /mnt/cni-bin ]; then
    # Install CNI plugin binary
    mkdir -p ${CNIBIN}
    cp ${ACIBIN}/opflex-agent-cni $CNIBIN
fi
if [ -w /mnt/cni-conf ]; then
    # Install CNI configuration
    mkdir -p /mnt/cni-conf/cni/net.d
    cat <<EOF > /mnt/cni-conf/cni/net.d/10-opflex-cni.conf
{
   "cniVersion": "0.3.1",
   "supportedVersions": [ "0.3.0", "0.3.1" ],
   "name": "k8s-pod-network",
   "type": "opflex-agent-cni",
   "ipam": {"type": "opflex-agent-cni-ipam"}
}
EOF
fi

if [ -w ${PREFIX} ]; then
    # Setup folders to hold metadata
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/endpoints
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/services
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/snats
    mkdir -p ${VARDIR}/lib/aci-containers/k8s-pod-network
fi

function check_eth {
    ip link show "$1" | grep -q "$1"
}

function get_ip {
    ip addr show "$1" | grep -o 'inet [0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+' | grep -o [0-9].*
}

function get_mac {
    ip link show "$1" | awk '/ether/ {print $2}'
}

# Add host access links
if check_eth veth_host; then
    echo "veth_host already exists, skip creation"
else
    ip link add veth_host type veth peer name veth_host_ac
    PEER=$(ip link | grep @veth_host: | awk '{print $2}' | awk -F @ '{print $1}')
    ip link set $PEER name veth_host_ac
    ip link set veth_host up
    ip link set veth_host_ac up
fi
ACC_MAC=$(get_mac veth_host)

# FIXME Let deployment decide interface name
if check_eth eth0; then
    VTEP_IP=$(get_ip eth0)
    VTEP_IFACE=eth0
elif check_eth enp0s8; then
    VTEP_IP=$(get_ip enp0s8)
    VTEP_IFACE=enp0s8
else
    echo "VTEP interface not found"
fi

# FIXME make route addition based on pod subnet.
CHECK=$(ip route show 10.2.56.0/24 | wc -l)
if [ $CHECK -ne 0 ]; then
    ip route del 10.2.56.0/24
fi

ip route add 10.2.56.0/24 dev veth_host scope link src $VTEP_IP

# Allow pod traffic to go out of veth_host
iptables -A FORWARD -i veth_host -j ACCEPT

# SNAT outgoing traffic from pod to external world
iptables -t nat -A POSTROUTING -o $VTEP_IFACE -j MASQUERADE

# Create Host EP file
UUID=${HOSTNAME}_${VTEP_IP}_veth_host_ac
#FNAME=${UUID}.ep
FNAME=veth_host_ac.ep

cat <<EOF > ${VARDIR}/lib/opflex-agent-ovs/endpoints/${FNAME}
{
  "uuid": "$UUID",
  "eg-policy-space": "kube",
  "endpoint-group-name": "kubernetes|kube-nodes",
  "ip": [
    "$VTEP_IP"
  ],
  "mac": "$ACC_MAC",
  "access-interface": "veth_host_ac",
  "access-uplink-interface": "pa-veth_host_ac",
  "interface-name": "pi-veth_host_ac",
  "attributes": {
    "app": "host-access",
    "interface-name": "veth_host_ac",
    "namespace": "default",
    "vm-name": "host-access"
  }
}
EOF

cat ${VARDIR}/lib/opflex-agent-ovs/endpoints/${FNAME}

CMD=${HOSTAGENT}
if [ -f ${HOSTAGENT_CONF} ]; then
    CMD="${CMD} -config-path ${HOSTAGENT_CONF}"
fi
if [ -f ${KUBECONFIG} ]; then
    CMD="${CMD} -kubeconfig ${KUBECONFIG}"
fi
    
exec ${CMD}

