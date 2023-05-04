#!/bin/bash
# usage: build_openvswitch.sh docker-id :tag

set -x

DOCKER_HUB_ID=$1
DOCKER_TAG=$2

http_proxy="http://proxy.esl.cisco.com:80"
https_proxy="http://proxy.esl.cisco.com:80"
no_proxy="engci-jenkins-sjc.cisco.com,172.28.184.12"

export http_proxy
export https_proxy
export no_proxy

#SECOPT="--security-opt seccomp=unconfined "
SECOPT=
export SECOPT
#BUILDARG="--build-arg HTTP_PROXY=http://proxy.esl.cisco.com:80 --build-arg HTTPS_PROXY=http://proxy.esl.cisco.com:80 --build-arg NO_PROXY=engci-jenkins-sjc.cisco.com,172.28.184.12 "
BUILDARG=
export BUILDARG

if [ "$#" -ne 2 ]; then
  echo "usage: build_openvswitch.sh docker-id :tag"
  exit -1
fi

DOCKER_DIR=.
rm -Rf build/openvswitch
[ -z "$DOCKER_TAG" ] && DOCKER_TAG=
export DOCKER_HUB_ID
export DOCKER_TAG

set -Eeuxo pipefail

echo "starting ovs build"
echo "building base image"
rm -Rf build/openvswitch
mkdir -p build/openvswitch
cp $DOCKER_DIR/Dockerfile-openvswitch-base build/openvswitch
docker build $BUILDARG -t $DOCKER_HUB_ID/openvswitch-base$DOCKER_TAG -f ./build/openvswitch/Dockerfile-openvswitch-base build/openvswitch

echo "copying intermediate binaries and libs"
rm -Rf build/openvswitch/dist
mkdir -p build/openvswitch/dist/usr/local
id=$(docker create $DOCKER_HUB_ID/openvswitch-base$DOCKER_TAG)
docker cp -L $id:/usr/local/lib build/openvswitch/dist/usr/local
docker cp -L $id:/usr/local/bin build/openvswitch/dist/usr/local
docker cp -L $id:/usr/local/sbin build/openvswitch/dist/usr/local
docker cp -L $id:/usr/local/share build/openvswitch/dist/usr/local
docker rm -v $id
cp $DOCKER_DIR/launch-ovs.sh build/openvswitch/dist/usr/local/bin
cp $DOCKER_DIR/liveness-ovs.sh build/openvswitch/dist/usr/local/bin
cp $DOCKER_DIR/../../dist-static/ovsresync build/openvswitch/dist/usr/local/bin

echo "building final image"
cp $DOCKER_DIR/Dockerfile-openvswitch build/openvswitch
docker build $BUILDARG -t $DOCKER_HUB_ID/openvswitch$DOCKER_TAG -f ./build/openvswitch/Dockerfile-openvswitch build/openvswitch/dist
docker push $DOCKER_HUB_ID/openvswitch$DOCKER_TAG
