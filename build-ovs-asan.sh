#!/bin/bash

set -x
DOCKER_HUB_ID=$1
DOCKER_TAG=$2

echo "starting openvswitch asan bbuild"
docker build -t $DOCKER_HUB_ID/openvswitch$DOCKER_TAG -f docker/Dockerfile-openvswitch-asan .
docker push $DOCKER_HUB_ID/openvswitch$DOCKER_TAG
