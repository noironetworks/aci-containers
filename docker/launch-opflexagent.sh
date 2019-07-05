#!/bin/sh

set -e
set -x

PREFIX=/usr/local
VARDIR=${PREFIX}/var
OPFLEXAGENT=${PREFIX}/bin/opflex_agent
OPFLEXAGENT_CONF_PATH=/usr/local/etc/opflex-agent-ovs
OPFLEXAGENT_DISABLED_CONF=${OPFLEXAGENT_CONF_PATH}/opflex-agent.conf
OPFLEXAGENT_BASE_CONF=${OPFLEXAGENT_CONF_PATH}/base-conf.d
OPFLEXAGENT_CONFD=${OPFLEXAGENT_CONF_PATH}/conf.d

if [ -w ${PREFIX} ]; then
    # Setup folders to hold metadata
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/endpoints
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/services
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/ids
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/mcast
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/snats
fi

if [ -d ${OPFLEXAGENT_CONF_PATH} ]; then
    cat <<EOF > ${OPFLEXAGENT_DISABLED_CONF}
{
    "opflex": {
        "name": "disabled",
        "domain": "disabled",
        "ssl": {
            "mode": "encrypted",
            "ca-store": "/etc/ssl/certs/"
        }
    }
}
EOF
fi

exec ${OPFLEXAGENT} -w \
     -c ${OPFLEXAGENT_DISABLED_CONF} \
     -c ${OPFLEXAGENT_BASE_CONF} \
     -c ${OPFLEXAGENT_CONFD}
