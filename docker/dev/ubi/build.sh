#!/bin/bash

set -x

docker build --build-arg HTTP_PROXY=$http_proxy --build-arg HTTPS_PROXY=$https_proxy --build-arg NO_PROXY=$no_proxy -t noirolabs/ubibase-opflex-build-base -f Dockerfile-ubibase-opflex-build-base
docker build --build-arg HTTP_PROXY=$http_proxy --build-arg HTTPS_PROXY=$https_proxy --build-arg NO_PROXY=$no_proxy -t noirolabs/ubibase-opflex -f Dockerfile-ubibase-opflex
docker build --build-arg HTTP_PROXY=$http_proxy --build-arg HTTPS_PROXY=$https_proxy --build-arg NO_PROXY=$no_proxy -t noirolabs/ubibase-aci -f Dockerfile-ubibase-aci

docker push noirolabs/ubibase-opflex-build-base
docker push noirolabs/ubibase-opflex
docker push noirolabs/ubibase-aci

