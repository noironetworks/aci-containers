#!/bin/bash

set -e
set -x

CNIBIN=/mnt/cni-bin/cni/bin
PREFIX=/usr/local
VARDIR=${PREFIX}/var
ACIBIN=${PREFIX}/bin
HOSTAGENT=${ACIBIN}/aci-containers-host-agent
HOSTAGENT_CONF=/usr/local/etc/aci-containers/host-agent.conf
KUBECONFIG=/usr/local/etc/kubeconfig

if [ -w /mnt/cni-bin ]; then
    # Install CNI plugin binary
    mkdir -p ${CNIBIN}
    cp ${ACIBIN}/opflex-agent-cni $CNIBIN
fi

#Chained mode
if [ -z != $CHAINED_MODE ] && [ "$CHAINED_MODE" == "true" ] && [ -z != $PRIMARY_CNI_PATH ]; then
    IN_CHAINED_MODE="true"
    CHAINEDACICNI=$(echo "\
{\
  \"supportedVersions\": [ \"0.3.0\", \"0.3.1\", \"0.4.0\" ],\
  \"type\": \"opflex-agent-cni\",\
  \"chaining-mode\": true,\
  \"log-level\": \"debug\",\
  \"log-file\": \"/var/log/opflexagentcni.log\"\
}")
    if [ -w  $PRIMARY_CNI_PATH ]; then
        MULTUS=$(jq '.type=="multus"' $PRIMARY_CNI_PATH)
        if [ "$MULTUS" == "true" ]; then
            #Primary CNI is multus
            SEARCHDELEGATES=$(jq '.delegates | length' $PRIMARY_CNI_PATH)
	    if [ "$SEARCHDELEGATES" == 0 ]; then
                CONTENTS=$(jq --argjson CHAINED "$CHAINEDACICNI" '. | .delegates=[$CHAINED]' $PRIMARY_CNI_PATH)
                echo $CONTENTS>$PRIMARY_CNI_PATH
	    else
                PRESENT=$(jq '.delegates | [.[] | select(.type=="opflex-agent-cni")] | length' $PRIMARY_CNI_PATH)
	      if [ "$PRESENT" == 0 ]; then
                CONTENTS=$(jq --argjson CHAINED "$CHAINEDACICNI" '.delegates |= [.[],$CHAINED]' $PRIMARY_CNI_PATH)
                echo $CONTENTS>$PRIMARY_CNI_PATH
	      fi
	    fi
        else
	    #Primary CNI is not multus
            SEARCHCHAIN=$(jq '.plugins | length' $PRIMARY_CNI_PATH)
            if [ "$SEARCHCHAIN" == 0 ]; then
                NAME=$(jq '.name' $PRIMARY_CNI_PATH)
                CNIVERSION=$(jq '.cniVersion' $PRIMARY_CNI_PATH)
                CONTENTS=$(jq --argjson NAME "$NAME" --argjson CHAINED "$CHAINEDACICNI" --argjson CNIVERSION "$CNIVERSION" '{"name":$NAME, "cniVersion":$CNIVERSION, "plugins":[.,$CHAINED]}' $PRIMARY_CNI_PATH)
                echo $CONTENTS>$PRIMARY_CNI_PATH
            else
              PRESENT=$(jq '.plugins | [.[] | select(.type=="opflex-agent-cni")] | length' $PRIMARY_CNI_PATH)
              if [ "$PRESENT" == 0 ]; then
                CONTENTS=$(jq --argjson CHAINED "$CHAINEDACICNI" '.plugins |= [.[],$CHAINED]' $PRIMARY_CNI_PATH)
                echo $CONTENTS>$PRIMARY_CNI_PATH
              fi
            fi
	fi
    else
        echo "Primary CNI path $PRIMARY_CNI_PATH is not writable"
    fi
else
IN_CHAINED_MODE="false"
if [ -w /mnt/cni-conf ]; then
    INT_DURATION_WAIT_FOR_NETWORK=210
    if [ -z != $DURATION_WAIT_FOR_NETWORK ]; then
        INT_DURATION_WAIT_FOR_NETWORK=$((DURATION_WAIT_FOR_NETWORK))
    fi
    # Install CNI configuration
    mkdir -p /mnt/cni-conf/cni/net.d
    if [  -z !=  $DISABLE_WAIT_FOR_NETWORK ] && [ $DISABLE_WAIT_FOR_NETWORK = "True" ]; then
        cat <<EOF > /mnt/cni-conf/cni/net.d/01-opflex-cni.conf
{
   "cniVersion": "0.3.1",
   "supportedVersions": [ "0.3.0", "0.3.1", "0.4.0" ],
   "name": "k8s-pod-network",
   "type": "opflex-agent-cni",
   "ipam": {"type": "opflex-agent-cni-ipam"}
}
EOF
    else
        cat <<EOF > /mnt/cni-conf/cni/net.d/01-opflex-cni.conf
{
   "cniVersion": "0.3.1",
   "supportedVersions": [ "0.3.0", "0.3.1", "0.4.0" ],
   "name": "k8s-pod-network",
   "type": "opflex-agent-cni",
   "wait-for-network": true,
   "wait-for-network-duration": $((INT_DURATION_WAIT_FOR_NETWORK)),
   "ipam": {"type": "opflex-agent-cni-ipam"}
}
EOF
    fi
fi
fi

if [  -z !=  $MULTUS ] && [ $MULTUS = "True" ]; then
    mkdir -p /mnt/multus-cni-conf/cni/net.d
    cp -r /mnt/cni-conf/cni/net.d/* /mnt/multus-cni-conf/cni/net.d/
fi

if [ -w ${PREFIX} ]; then
    # Setup folders to hold metadata
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/endpoints
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/services
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/snats
    mkdir -p ${VARDIR}/lib/aci-containers/k8s-pod-network
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/reboot-conf.d
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/ids
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/droplog
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/faults
fi

if [ "$OPFLEX_MODE" == "overlay" ]; then
    echo "enabling host access for overlay mode"
    if [ "$OPFLEX_MODE" != "dpu" ]; then
        ${ACIBIN}/enable-hostacc.sh
    fi
else
    echo "running in on prem mode"
fi

if [ "$OPFLEX_MODE" != "dpu" ] && [ "$IN_CHAINED_MODE" != "true" ]; then
    ${ACIBIN}/enable-droplog.sh
fi

CMD=${HOSTAGENT}
if [ -f ${HOSTAGENT_CONF} ]; then
    CMD="${CMD} -config-path ${HOSTAGENT_CONF}"
fi
if [ -f ${KUBECONFIG} ]; then
    CMD="${CMD} -kubeconfig ${KUBECONFIG}"
fi
    
exec ${CMD}

