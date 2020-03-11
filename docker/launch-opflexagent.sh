#!/bin/sh

set -e
set -x

PREFIX=/usr/local
VARDIR=${PREFIX}/var
OPFLEXAGENT=${PREFIX}/bin/opflex_agent
OPFLEXAGENT_CONF_PATH=/usr/local/etc/opflex-agent-ovs
OPFLEXAGENT_REBOOT_CONFD=${VARDIR}/lib/opflex-agent-ovs/reboot-conf.d
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
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/reboot-conf.d
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/droplog
fi

if [ -d ${OPFLEXAGENT_CONF_PATH} ]; then
    cat <<EOF > ${OPFLEXAGENT_DISABLED_CONF}
{
    "opflex": {
        "name": "disabled",
        "domain": "disabled",
        "ssl": {
            "mode": "$SSL_MODE",
            "ca-store": "/etc/ssl/certs/"
        }
    }
}
EOF
fi

if [ "$REBOOT_WITH_OVS" == "true" ]; then
	exec ${OPFLEXAGENT} -w \
		 -c ${OPFLEXAGENT_DISABLED_CONF} \
		 -c ${OPFLEXAGENT_BASE_CONF} \
		 -c ${OPFLEXAGENT_CONFD} \
		 -c ${OPFLEXAGENT_REBOOT_CONFD}
else
	exec ${OPFLEXAGENT} -w \
		 -c ${OPFLEXAGENT_DISABLED_CONF} \
		 -c ${OPFLEXAGENT_BASE_CONF} \
		 -c ${OPFLEXAGENT_CONFD}
fi
