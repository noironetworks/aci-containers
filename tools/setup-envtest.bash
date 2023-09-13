#!/usr/bin/env bash

# Copyright 2018 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

 
# Enable tracing in this script off by setting the TRACE variable in your
# environment to any value:
#
# $ TRACE=1 test.sh
TRACE=${TRACE:-""}
if [ -n "${TRACE}" ]; then
  set -x
fi

#To upgrade envtest binaries set the k8sver to 
# the latest kubecontroller tools version
k8sver=1.27.1
goos=$(go env GOOS)
goarch=$(go env GOARCH)

FETCHBINARIES=1

if [ ${FETCHBINARIES} -eq 1 ]; then
cwd=`pwd`
 cd /tmp 
 kb_tools_archive_name="kubebuilder-tools-${k8sver}-${goos}-${goarch}.tar.gz"
 kb_tools_download_url="https://storage.googleapis.com/kubebuilder-tools/${kb_tools_archive_name}"
 curl -fsLO ${kb_tools_download_url}
 tar xzf ${kb_tools_archive_name}
 echo $cwd
cd $cwd 
#else
# echo "copying envtest binaries"
# mkdir -p /tmp/kubebuilder/bin
# cp -r tools/bin/kubebuilder/* /tmp/kubebuilder/bin
fi

setup_envs() 
{
 echo "setting up env vars"

 # Setup env vars
 export PATH=$PATH:/tmp/kubebuilder/bin
 export TEST_ASSET_KUBECTL=/tmp/kubebuilder/bin/kubectl
 export TEST_ASSET_KUBE_APISERVER=/tmp/kubebuilder/bin/kube-apiserver
 export TEST_ASSET_ETCD=/tmp/kubebuilder/bin/etcd
 export KUBEBUILDER_ASSETS=/tmp/kubebuilder/bin
}

