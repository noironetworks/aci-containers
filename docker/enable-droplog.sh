#!/bin/sh

PREFIX=/usr/local
VARDIR=${PREFIX}/var
DROPLOG_FNAME=a.droplogcfg
GENEVE=6081
LO_LISTEN=127.0.0.1:50000

echo "setting up drop-logs"

if [ ! -f ${VARDIR}/lib/opflex-agent-ovs/droplog/${DROPLOG_FNAME} ]; then
cat <<EOF > ${VARDIR}/lib/opflex-agent-ovs/droplog/${DROPLOG_FNAME}
{
     "drop-log-enable": true
}
EOF
fi

set -x
set +e

iptables -t nat -A OUTPUT -p udp --dport $GENEVE -j DNAT --to $LO_LISTEN -m comment --comment "drop-log-geneve-redirect"
retval=$?
if [ $retval -ne 0 ]; then
    echo "iptables not installed, trying nftables"
    nft list ruleset | grep "drop-log-geneve-redirect"
    retval=$?
    if [ $retval -ne 0 ]; then
        nft add table ip nat
        nft add chain ip nat OUTPUT
        nft add rule ip nat OUTPUT udp dport $GENEVE dnat to $LO_LISTEN comment "drop-log-geneve-redirect"
    fi
else
    # delete the rule we added to determine if iptables or nftables
    iptables -t nat -D OUTPUT -p udp --dport $GENEVE -j DNAT --to $LO_LISTEN -m comment --comment "drop-log-geneve-redirect"
    iptables-save | grep "drop-log-geneve-redirect"
    retval=$?
    if [ $retval -ne 0 ]; then
        # Redirect drop-log-geneve encapsulated packets to listening port
        iptables -t nat -A OUTPUT -p udp --dport $GENEVE -j DNAT --to $LO_LISTEN -m comment --comment "drop-log-geneve-redirect"
    fi
fi
