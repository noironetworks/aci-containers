#!/bin/sh

set -e
set -x

PREFIX=/usr/local
VARDIR=${PREFIX}/var
ACIBIN=${PREFIX}/bin
OPFLEXAGENT=${ACIBIN}/agent_ovs
OPFLEXAGENT_CONF_PATH=/usr/local/etc/opflex-agent-ovs
OPFLEXAGENT_BASE_CONF=${OPFLEXAGENT_CONF_PATH}/opflex-agent-ovs.conf
OPFLEXAGENT_RENDERER_CONF=${OPFLEXAGENT_CONF_PATH}/renderer.conf
OPFLEXAGENT_LOCAL_CONF=${OPFLEXAGENT_CONF_PATH}/conf.d/local.conf

if [ -w ${PREFIX} ]; then
    # Setup folders to hold metadata
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/endpoints
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/services
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/ids
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/mcast
fi

if [ -d ${OPFLEXAGENT_CONF_PATH} ]; then
    cat <<EOF > ${OPFLEXAGENT_BASE_CONF}
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

if [[ ${ACI_ENCAP_TYPE} = "vxlan" ]]; then
    cat <<EOF > ${OPFLEXAGENT_RENDERER_CONF}
{
    "renderers": {
        "stitched-mode": {
            "int-bridge-name": "br-int",
            "access-bridge-name": "br-access",
            "encap": {
                "vxlan" : {
                    "encap-iface": "br-int_vxlan0",
                    "uplink-iface": "${ACI_UPLINK_IFACE}.${ACI_INFRA_VLAN}",
                    "uplink-vlan": ${ACI_INFRA_VLAN},
                    "remote-ip": "10.0.0.32",
                    "remote-port": 8472
                }
            }
        }
    }
}
EOF

elif [[ ${ACI_ENCAP_TYPE} = "vlan" ]]; then
    cat <<EOF > ${OPFLEXAGENT_RENDERER_CONF}
{
    "renderers": {
        "stitched-mode": {
            "int-bridge-name": "br-int",
            "access-bridge-name": "br-access",
            "encap": {
                "vlan" : {
                    "encap-iface": "${ACI_UPLINK_IFACE}"
                }
            }
        }
    }
}
EOF

else
    echo Unsupported encap type ${ACI_ENCAP_TYPE}
    exit 1
fi

exec ${OPFLEXAGENT} \
     -c ${OPFLEXAGENT_BASE_CONF} \
     -c ${OPFLEXAGENT_RENDERER_CONF} \
     -c ${OPFLEXAGENT_LOCAL_CONF}
