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
k8s_vmm_domain = ${K8S_VMM_DOMAIN}
k8s_controller = ${K8S_VMM_CONTROLLER}

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
${AIMCTLRUN} manager topology-create
${AIMCTLRUN} manager vmm-policy-create Kubernetes --monitored=true
for tenant in `${AIMCTLRUN} manager tenant-find -p | tail -n+2`; do
    ${AIMCTLRUN} manager tenant-delete $tenant
done
TMON=$(for i in common ${APIC_MONITOR_TENANTS}; do echo $i; done|sort|uniq)
for tenant in ${TMON}; do
    ${AIMCTLRUN} manager tenant-create $tenant --monitored=true
done

echo Starting Aid
exec ${AIMAID} --config-dir "${AIMDIR}" --config-dir "${AIMLOCALDIR}"
