#!/bin/sh

set -e
set -x

PREFIX=/usr/local
AIMDIR=/usr/local/etc/aim
AIMLOCALDIR=/usr/local/etc/aim-local
AIMCONF=${AIMDIR}/aim.conf
AIMLOCALCONF=${AIMLOCALDIR}/aim-local.conf
AIMCTL=/usr/bin/aimctl
AIMAID=/usr/bin/aim-aid

mkdir -p "${AIMDIR}"
cat <<EOF > "${AIMCONF}"
[aim]
aim_store = k8s

[aim_k8s]
k8s_config_path =
k8s_namespace = kube-system

[apic]
# Hostname:port list of APIC controllers
apic_hosts = ${APIC_HOSTS}

# Username for the APIC controller
apic_username = ${APIC_USERNAME}
# Password for the APIC controller
apic_password = ${APIC_PASSWORD}

# Whether use SSl for connecting to the APIC controller or not
apic_use_ssl = True
scope_names = False
verify_ssl_certificate = False

apic_model = apicapi.db.noop_manager
EOF

${AIMCTL} -c "${AIMCONF}" -c "${AIMLOCALCONF}" config update

echo Starting Aid
exec ${AIMAID} --config-dir "${AIMDIR}" --config-dir "${AIMLOCALDIR}"
