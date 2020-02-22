#!/bin/sh

set -e
set -x

PREFIX=/usr/local
OPFLEXSERVER=${PREFIX}/bin/opflex_server
OPFLEXSERVER_POL_PATH=/usr/local/var/lib/opflex-server
OPFLEXSERVER_POL=${OPFLEXSERVER_POL_PATH}/policy.json
OPFLEXSERVER_CONF=${OPFLEXSERVER_POL_PATH}/config.json
mkdir -p ${OPFLEXSERVER_POL_PATH}

if [ ! -f ${OPFLEXSERVER_POL} ]; then
    cat <<EOF > ${OPFLEXSERVER_POL}
[
    {
    }
]
EOF
fi

if [ ! -f ${OPFLEXSERVER_CONF} ]; then
    cat <<EOF > ${OPFLEXSERVER_CONF}
{
}
EOF
fi

exec ${OPFLEXSERVER} --level=debug2 --policy=${OPFLEXSERVER_POL} --grpc_conf=${OPFLEXSERVER_CONF} $@
