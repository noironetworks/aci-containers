#!/bin/sh

set -e
set -x

PREFIX=/usr/local
VARDIR=${PREFIX}/var
ACIBIN=${PREFIX}/bin
HOSTAGENT=${ACIBIN}/aci-containers-host-agent

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

vtep=$($HOSTAGENT -get-vtep)
retval=$?
if [ $retval -ne 0 ]; then
    echo "error getting vtep"
    exit $retval
else
read VTEP_IFACE VTEP_IP_CIDR <<EOF
    $vtep
EOF
fi

echo "using vtep $VTEP_IFACE $VTEP_IP_CIDR"

if [[ ! -z "$VTEP_IFACE" && ! -z "$VTEP_IP_CIDR" ]]; then

    set +e

    iptables -A FORWARD -i veth_host -j ACCEPT
    retval=$?
    if [ $retval -ne 0 ]; then
        echo "iptables not installed, trying nftables"
        nft list ruleset | grep  veth_host
        retval=$?
        if [ $retval -ne 0 ]; then
            # Allow pod traffic to go out of veth_host
            nft add table ip filter
            nft add chain ip filter FORWARD
            nft add rule ip filter FORWARD iifname veth_host counter accept

            # SNAT outgoing traffic from pod to external world
            nft add table ip nat
            nft add chain ip nat POSTROUTING
            nft add rule ip nat POSTROUTING oif $VTEP_IFACE masquerade
        fi
    else
	# delete the rule we added to deterime if iptables or nftables
	iptables -D FORWARD -i veth_host -j ACCEPT
        iptables-save | grep veth_host
        retval=$?
        if [ $retval -ne 0 ]; then
            # Allow pod traffic to go out of veth_host
            iptables -A FORWARD -i veth_host -j ACCEPT
            # SNAT outgoing traffic from pod to external world
            iptables -t nat -A POSTROUTING -o $VTEP_IFACE -j MASQUERADE
        fi
    fi

    set -e

    VTEP_IP=$(echo $VTEP_IP_CIDR | awk -F '/' '{print $1}')
    # Create Host EP file
    UUID=${HOSTNAME}_${VTEP_IP}_veth_host_ac
    #FNAME=${UUID}.ep
    FNAME=veth_host_ac.ep

cat <<EOF > ${VARDIR}/lib/opflex-agent-ovs/endpoints/${FNAME}
{
  "uuid": "$UUID",
  "eg-policy-space": "$TENANT",
  "endpoint-group-name": "$NODE_EPG",
  "ip": [
    "$VTEP_IP_CIDR"
  ],
  "mac": "$ACC_MAC",
  "disable-adv": true,
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
fi
