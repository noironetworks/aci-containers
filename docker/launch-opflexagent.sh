#!/bin/sh

set -e
set -x

PREFIX=/usr/local
VARDIR=${PREFIX}/var
ACIBIN=${PREFIX}/bin
OPFLEXAGENT=${ACIBIN}/agent_ovs
OPFLEXAGENT_CONF_PATH=/usr/local/etc/opflex-agent-ovs
OPFLEXAGENT_LOCAL_CONF=${OPFLEXAGENT_CONF_PATH}/conf.d/local.conf

if [ -w ${PREFIX} ]; then
    # Setup folders to hold metadata
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/endpoints
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/services
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/ids
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/mcast
fi

if [ -d ${OPFLEXAGENT_CONF_PATH} ]; then
    cat <<EOF > ${OPFLEXAGENT_CONF_PATH}/opflex-agent-ovs.conf
{
    "log": {
        "level": "info"
    },
    "opflex": {
        "name": "${KUBERNETES_NODE_NAME}",
        "peers": [
            {"hostname": "10.0.0.30", "port": "8009"}
        ],
        "ssl": {
            "mode": "encrypted",
            "ca-store": "/etc/ssl/certs/"
        }
    },
    "endpoint-sources": {
        "filesystem": ["${VARDIR}/lib/opflex-agent-ovs/endpoints"]
    },
    "service-sources": {
        "filesystem": ["${VARDIR}/lib/opflex-agent-ovs/services"]
    }
}
EOF

fi

exec ${OPFLEXAGENT} \
     -c ${OPFLEXAGENT_CONF_PATH}/opflex-agent-ovs.conf \
     -c ${OPFLEXAGENT_LOCAL_CONF}
