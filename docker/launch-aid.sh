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
AIMCTLRUN="${AIMCTL} -c ${AIMCONF} -c ${AIMLOCALCONF}"

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

${AIMCTLRUN} config update

for pod in `${AIMCTLRUN} manager pod-find -p | tail -n+2`; do
    ${AIMCTLRUN} manager pod-delete $pod
done
for pod in ${APIC_VMM_POD}; do
    ${AIMCTLRUN} manager pod-create $pod --monitored=true
done

for tenant in `${AIMCTLRUN} manager tenant-find -p | tail -n+2`; do
    ${AIMCTLRUN} manager tenant-delete $tenant
done
${AIMCTLRUN} \
	  manager tenant-create common --monitored=true
if [ ${APIC_L3OUT_TENANT} -ne "common" ]; then
    ${AIMCTLRUN} manager tenant-create ${APIC_L3OUT_TENANT} --monitored=true
fi

echo Starting Aid
exec ${AIMAID} --config-dir "${AIMDIR}" --config-dir "${AIMLOCALDIR}"
