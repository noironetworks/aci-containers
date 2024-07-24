#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname ${PWD})

vendor/k8s.io/code-generator/kube_codegen.sh all \
  github.com/noironetworks/aci-containers/pkg/istiocrd github.com/noironetworks/aci-containers/pkg/istiocrd/apis \
  aci.istio:v1 \
  --go-header-file ${SCRIPT_ROOT}/aci-containers/crd-code-generation/hack/custom-boilerplate.go.txt
