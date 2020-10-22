#!/bin/bash

set -x

export http_proxy=http://proxy.esl.cisco.com:80
export https_proxy=http://proxy.esl.cisco.com:80
export no_proxy=engci-jenkins-sjc.cisco.com,172.28.184.12

docker build --build-arg HTTP_PROXY=$http_proxy --build-arg HTTPS_PROXY=$https_proxy --build-arg NO_PROXY=$no_proxy -t registry.hub.docker.com/noirolabs/ubibase-opflex-build-base -f Dockerfile-ubibase-opflex-build-base
docker build --build-arg HTTP_PROXY=$http_proxy --build-arg HTTPS_PROXY=$https_proxy --build-arg NO_PROXY=$no_proxy -t registry.hub.docker.com/noirolabs/ubibase-opflex -f Dockerfile-ubibase-opflex
docker build --build-arg HTTP_PROXY=$http_proxy --build-arg HTTPS_PROXY=$https_proxy --build-arg NO_PROXY=$no_proxy -t registry.hub.docker.com/noirolabs/ubibase-aci -f Dockerfile-ubibase-aci

docker push registry.hub.docker.com/noirolabs/ubibase-opflex-build-base
docker push registry.hub.docker.com/noirolabs/ubibase-opflex
docker push registry.hub.docker.com/noirolabs/ubibase-aci

