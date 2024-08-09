#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname ${PWD})

source vendor/k8s.io/code-generator/kube_codegen.sh

kube::codegen::gen_client --with-applyconfig --with-watch $SCRIPT_ROOT/aci-containers/pkg/fabricattachment/apis --output-dir $SCRIPT_ROOT/aci-containers/pkg/fabricattachment --output-pkg github.com/noironetworks/aci-containers/pkg/fabricattachment --boilerplate $SCRIPT_ROOT/aci-containers/crd-code-generation/hack/custom-boilerplate.go.txt
