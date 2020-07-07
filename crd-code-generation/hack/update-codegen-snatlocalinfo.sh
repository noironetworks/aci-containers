#!/bin/bash
set -x
set -e
set -o errexit
set -o nounset
#set -o pipefail

SCRIPT_ROOT=$(dirname ${PWD})

vendor/k8s.io/code-generator/generate-groups.sh all \
  github.com/noironetworks/aci-containers/pkg/snatlocalinfo github.com/noironetworks/aci-containers/pkg/snatlocalinfo/apis \
  aci.snat:v1 \
  --go-header-file ${SCRIPT_ROOT}/aci-containers/crd-code-generation/hack/custom-boilerplate.go.txt
