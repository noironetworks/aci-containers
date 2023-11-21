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
    rm -f ${CNIBIN}/opflex-agent-cni
    cp ${ACIBIN}/opflex-agent-cni $CNIBIN
fi
if [ -w /mnt/cni-conf ]; then
    INT_DURATION_WAIT_FOR_NETWORK=210
    if [ -z != $DURATION_WAIT_FOR_NETWORK ]; then
        INT_DURATION_WAIT_FOR_NETWORK=$((DURATION_WAIT_FOR_NETWORK))
    fi
    # Install CNI configuration
    mkdir -p /mnt/cni-conf/cni/net.d
    if [  -z !=  $DISABLE_WAIT_FOR_NETWORK ] && [ $DISABLE_WAIT_FOR_NETWORK = "True" ]; then
        cat <<EOF > /mnt/cni-conf/cni/net.d/01-opflex-cni.conf
{
   "cniVersion": "0.3.1",
   "supportedVersions": [ "0.3.0", "0.3.1", "0.4.0" ],
   "name": "k8s-pod-network",
   "type": "opflex-agent-cni",
   "ipam": {"type": "opflex-agent-cni-ipam"}
}
EOF
    else
        cat <<EOF > /mnt/cni-conf/cni/net.d/01-opflex-cni.conf
{
   "cniVersion": "0.3.1",
   "supportedVersions": [ "0.3.0", "0.3.1", "0.4.0" ],
   "name": "k8s-pod-network",
   "type": "opflex-agent-cni",
   "wait-for-network": true,
   "wait-for-network-duration": $((INT_DURATION_WAIT_FOR_NETWORK)),
   "ipam": {"type": "opflex-agent-cni-ipam"}
}
EOF
    fi
fi

if [  -z !=  $MULTUS ] && [ $MULTUS = "True" ]; then
    mkdir -p /mnt/multus-cni-conf/cni/net.d
    cp -r /mnt/cni-conf/cni/net.d/* /mnt/multus-cni-conf/cni/net.d/
fi

if [ -w ${PREFIX} ]; then
    # Setup folders to hold metadata
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/endpoints
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/services
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/snats
    mkdir -p ${VARDIR}/lib/aci-containers/k8s-pod-network
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/reboot-conf.d
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/ids
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/droplog
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/faults
fi

if [ "$OPFLEX_MODE" == "overlay" ]; then
    echo "enabling host access for overlay mode"
    ${ACIBIN}/enable-hostacc.sh
else
    echo "running in on prem mode"
fi

${ACIBIN}/enable-droplog.sh

CMD=${HOSTAGENT}
if [ -f ${HOSTAGENT_CONF} ]; then
    CMD="${CMD} -config-path ${HOSTAGENT_CONF}"
fi
if [ -f ${KUBECONFIG} ]; then
    CMD="${CMD} -kubeconfig ${KUBECONFIG}"
fi
    
exec ${CMD}

