#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname ${PWD})

source vendor/k8s.io/code-generator/kube_codegen.sh

PKG_NAME="oobpolicy"
OUTPUT_PKG="github.com/noironetworks/aci-containers/pkg/${PKG_NAME}"
GROUP="aci.oob"
VERSION="v1"

# Generate deepcopy
kube::codegen::gen_helpers \
    --boilerplate "${SCRIPT_ROOT}/aci-containers/crd-code-generation/hack/custom-boilerplate.go.txt" \
    "${SCRIPT_ROOT}/aci-containers/pkg/${PKG_NAME}/apis/${GROUP}/${VERSION}"

# Generate the clientset, listers, and informers
kube::codegen::gen_client \
    --with-applyconfig \
    --with-watch \
    "${SCRIPT_ROOT}/aci-containers/pkg/${PKG_NAME}/apis" \
    --output-dir "${SCRIPT_ROOT}/aci-containers/pkg/${PKG_NAME}" \
    --output-pkg "${OUTPUT_PKG}" \
    --boilerplate "${SCRIPT_ROOT}/aci-containers/crd-code-generation/hack/custom-boilerplate.go.txt"
