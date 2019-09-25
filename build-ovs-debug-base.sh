#!/bin/bash

set -x
DOCKER_HUB_ID=$1
DOCKER_TAG=$2

echo "starting openvswitch debug build"
docker build -t $DOCKER_HUB_ID/openvswitch-debug-base$DOCKER_TAG -f docker/Dockerfile-openvswitch-debug-base .
docker push $DOCKER_HUB_ID/openvswitch-debug-base$DOCKER_TAG
