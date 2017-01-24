#!/bin/sh

set -e
set -x

CNIBIN=/opt/cni/bin
PREFIX=/usr/local
VARDIR=${PREFIX}/var
ACIBIN=${PREFIX}/bin
HOSTAGENT=${ACIBIN}/aci-containers-host-agent
HOSTAGENT_CONF=/usr/local/etc/aci-containers/host-agent.conf

if [ -w /opt ]; then
    # Install CNI plugin binary
    mkdir -p ${CNIBIN}
    cp ${ACIBIN}/opflex-agent-cni $CNIBIN
fi
if [ -w /etc ]; then
    # Install CNI configuration
    mkdir -p /etc/cni/net.d
    cat <<EOF > /etc/cni/net.d/10-opflex-cni.conf
{
   "cniVersion": "0.2.0",
   "name": "k8s-pod-network",
   "type": "opflex-agent-cni",
}
EOF
fi

if [ -w ${PREFIX} ]; then
    # Setup folders to hold metadata
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/endpoints
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/services
    mkdir -p ${VARDIR}/lib/aci-containers/k8s-pod-network
fi
  
if [ -f ${HOSTAGENT_CONF} ]; then
    exec ${HOSTAGENT} -config-path ${HOSTAGENT_CONF}
else
    exec ${HOSTAGENT}
fi

