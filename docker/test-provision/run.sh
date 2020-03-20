#!/bin/sh

if [ -z ${APIC_IP+x} ]
then
    echo "APIC_IP needs to be set"
    exit 1
fi

if [ -z ${APIC_PASSWORD+x} ]
then
    echo "APIC_PASSWORD needs to be set"
    exit 1
fi

if [ -z ${TENANT+x} ]
then
    echo "TENANT needs to be set"
    exit 1
fi

if [ -z ${REGION+x} ]
then
    echo "REGION needs to be set"
    exit 1
fi

sed "s/APIC_IP/$APIC_IP/g ; s/TENANT/$TENANT/g ; s/UNDERLAY_VRF/${TENANT}_underlay/g ; s/CLOUD_REGION/$REGION/g" config.yaml.template > ./config.yaml
sed -i "s/host_agent_cni_bin_path: \/var\/lib/host_agent_cni_bin_path: \/opt/g ; s/host_agent_cni_conf_path: \/etc\/kubernetes/host_agent_cni_conf_path: \/etc/g" flavors.yaml

./acc_provision.py -f eks -a -c ./config.yaml -u admin -p $APIC_PASSWORD -o /output/cni.yaml
cp -r ./kube /output
echo "Created the necessary yaml files in the output directory"
