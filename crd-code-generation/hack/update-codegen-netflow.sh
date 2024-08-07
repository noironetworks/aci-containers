#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname ${PWD})

vendor/k8s.io/code-generator/kube_codegen.sh all \
  github.com/noironetworks/aci-containers/pkg/netflowpolicy github.com/noironetworks/aci-containers/pkg/netflowpolicy/apis \
  aci.netflow:v1alpha \
  --go-header-file ${SCRIPT_ROOT}/aci-containers/crd-code-generation/hack/custom-boilerplate.go.txt
