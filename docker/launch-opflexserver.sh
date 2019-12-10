#!/bin/sh

set -e
set -x

PREFIX=/usr/local
OPFLEXSERVER=${PREFIX}/bin/mock_server
OPFLEXSERVER_CONF_PATH=/usr/local/etc/opflex-server
OPFLEXSERVER_CONF=${OPFLEXSERVER_CONF_PATH}/policy.json
mkdir -p ${OPFLEXSERVER_CONF_PATH}

if [ ! -f ${OPFLEXSERVER_CONF} ]; then
    cat <<EOF > ${OPFLEXSERVER_CONF}
[
    {
    }
]
EOF
fi

exec ${OPFLEXSERVER} --policy=${OPFLEXSERVER_CONF} $@
