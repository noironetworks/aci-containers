#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname ${PWD})

vendor/k8s.io/code-generator/generate-groups.sh all \
  github.com/noironetworks/aci-containers/pkg/accprovisioninput github.com/noironetworks/aci-containers/pkg/accprovisioninput/apis \
  aci.ctrl:v1alpha1 \
  --go-header-file ${SCRIPT_ROOT}/aci-containers/crd-code-generation/hack/custom-boilerplate.go.txt
