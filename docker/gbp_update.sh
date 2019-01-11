#!/bin/sh
DST=/usr/local/etc/opflex-server/policy.json
POD=$(kubectl get pods -n kube-system --field-selector status.podIP=$1 -l name=aci-containers-host -o custom-columns=":metadata.name" | grep aci)
kubectl cp /tmp/gen_policy.$1.json kube-system/$POD:$DST -c opflex-server
