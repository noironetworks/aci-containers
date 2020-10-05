#!/bin/bash
# Build opflex and aci-containers private images in non jenkins environment
# 1. go get github.com/noironetworks/aci-containers
# 2. mkdir -p $HOME/work && cd $HOME/work
# 3. git clone https://github.com/noironetworks/opflex opflex
# 4. docker login as DOCKER_HUB_ID
# 5. cd docker && git checkout * when switching between UBI and Alpine builds
# usage: build_priv.sh <ubi|alpine> docker-id :tag
# example: ./build-priv.sh <alpine|ubi> challa :demo
set -x

TYPE=$1
DOCKER_HUB_ID=$2
DOCKER_TAG=$3

UBI_URI="registry.access.redhat.com\/ubi8\/ubi:latest"
UBI_MIN_URI="registry.access.redhat.com\/ubi8\/ubi-minimal:latest"
UBIBASE_OPFLEX="noirolabs\/ubibase-opflex:latest"
UBIBASE_OPFLEX_BUILD_BASE="noirolabs\/ubibase-opflex-build-base:latest"
UBIBASE_ACI="noirolabs\/ubibase-aci:latest"

opflex_arr='Dockerfile-opflex Dockerfile-opflexserver'
containers_arr='Dockerfile-controller Dockerfile-host Dockerfile-cnideploy Dockerfile-gbpserver Dockerfile-openvswitch'

if [ "$#" -ne 3 ]; then
  echo "usage: build_priv.sh <ubi|alpine> docker-id :tag"
  exit -1
fi

if [[ $TYPE == "alpine" ]]; then
   echo "Starting Alpine build"
   DOCKER_DIR=docker/dev/alpine
elif [[ $TYPE == "ubi" ]]; then
   echo "Starting Ubi build"
   DOCKER_DIR=docker
   sed -i -e "s/FROM ${UBI_MIN_URI}/FROM ${UBIBASE_OPFLEX_BUILD_BASE}/g" -e ':a;N;$!ba;s/RUN microdnf.*microdnf clean all/RUN :/g' \
     $DOCKER_DIR/Dockerfile-opflex-build-base
   for c in $opflex_arr; do
     sed -i -e "s/FROM ${UBI_URI}/FROM ${UBIBASE_OPFLEX}/g" -e ':a;N;$!ba;s/RUN yum.*yum clean all/RUN :/g' $DOCKER_DIR/$c
   done
   for c in $containers_arr; do
     sed -i -e "s/FROM ${UBI_URI}/FROM ${UBIBASE_ACI}/g" -e ':a;N;$!ba;s/RUN yum.*yum clean all/RUN :/g' $DOCKER_DIR/$c
   done
fi

# Modify docker/Dockerfile-opflex-build to reflect DOCKER_HUB_ID and  DOCKER_TAG
sed -i -e "s/FROM noiro\/opflex-build-base/FROM $DOCKER_HUB_ID\/opflex-build-base$DOCKER_TAG/g" \
           $DOCKER_DIR/Dockerfile-opflex-build


[ -z "$GOPATH" ] && GOPATH=$HOME/go
export GOPATH
ACICONTAINERS_DIR=.

[ -z "$OPFLEX_DIR" ] && OPFLEX_DIR=$HOME/work/opflex
export OPFLEX_DIR

[ -z "$DOCKER_TAG" ] && DOCKER_TAG=
export DOCKER_HUB_ID
export DOCKER_TAG

set -Eeuxo pipefail

echo "starting opflex build"

pushd $ACICONTAINERS_DIR
rm -Rf build
docker build -t $DOCKER_HUB_ID/opflex-build-base$DOCKER_TAG -f $DOCKER_DIR/Dockerfile-opflex-build-base docker
#docker push $DOCKER_HUB_ID/opflex-build-base$DOCKER_TAG

pushd $OPFLEX_DIR/genie
mvn compile exec:java
popd
docker build -t $DOCKER_HUB_ID/opflex-build$DOCKER_TAG -f $DOCKER_DIR/Dockerfile-opflex-build $OPFLEX_DIR
#docker push $DOCKER_HUB_ID/opflex-build$DOCKER_TAG

mkdir -p build/opflex/dist
docker run $DOCKER_HUB_ID/opflex-build$DOCKER_TAG tar -c -C /usr/local \
	bin/opflex_agent bin/gbp_inspect bin/mcast_daemon bin/opflex_server bin/map_ctrl bin/bpf bin/ip bin/tc \
	| tar -x -C build/opflex/dist
docker run -w /usr/local $DOCKER_HUB_ID/opflex-build$DOCKER_TAG /bin/sh -c 'find lib \(\
	 -name '\''libopflex*.so*'\'' -o \
	 -name '\''libmodelgbp*so*'\'' -o \
	 -name '\''libopenvswitch*so*'\'' -o \
         -name '\''libprometheus-cpp-*so*'\'' -o \
	 -name '\''libsflow*so*'\'' -o \
	 -name '\''libofproto*so*'\'' -o \
	 -name '\''libgrpc*so*'\'' -o \
	 -name '\''libproto*so*'\'' -o \
	 -name '\''libre2*so*'\'' -o \
	 -name '\''libupb*so*'\'' -o \
	 -name '\''libabsl*so*'\'' -o \
	 -name '\''libssl*so*'\'' -o \
	 -name '\''libcrypto*so*'\'' -o \
	 -name '\''libaddress_sorting*so*'\'' -o \
	 -name '\''libgpr*so*'\'' -o \
	 -name '\''bpf'\'' \
           \) ! -name '\''*debug'\'' \
           | xargs tar -c ' \
	  | tar -x -C build/opflex/dist
docker run -w /usr/local $DOCKER_HUB_ID/opflex-build$DOCKER_TAG /bin/sh -c \
	'find lib bin -name '\''*.debug'\'' | xargs tar -cz' \
	 > opflex-debuginfo.tar.gz
cp docker/launch-opflexagent.sh build/opflex/dist/bin/
cp docker/launch-mcastdaemon.sh build/opflex/dist/bin/
cp docker/launch-opflexserver.sh build/opflex/dist/bin/
cp -Rf docker/licenses build/opflex/dist
cp $DOCKER_DIR/Dockerfile-opflex build/opflex/dist/
cp $DOCKER_DIR/Dockerfile-opflexserver build/opflex/dist/

docker build -t $DOCKER_HUB_ID/opflex$DOCKER_TAG -f ./build/opflex/dist/Dockerfile-opflex build/opflex/dist
docker push $DOCKER_HUB_ID/opflex$DOCKER_TAG
docker build -t $DOCKER_HUB_ID/opflex-server$DOCKER_TAG -f ./build/opflex/dist/Dockerfile-opflexserver build/opflex/dist
docker push $DOCKER_HUB_ID/opflex-server$DOCKER_TAG

echo "starting aci-containers build"
rm -Rf dist-static
make all-static
make go-gbp-build
make go-build

docker build -t $DOCKER_HUB_ID/aci-containers-controller$DOCKER_TAG -f $DOCKER_DIR/Dockerfile-controller .
docker push $DOCKER_HUB_ID/aci-containers-controller$DOCKER_TAG

docker build -t $DOCKER_HUB_ID/aci-containers-host$DOCKER_TAG -f $DOCKER_DIR/Dockerfile-host .
docker push $DOCKER_HUB_ID/aci-containers-host$DOCKER_TAG

docker build -t $DOCKER_HUB_ID/cnideploy$DOCKER_TAG -f $DOCKER_DIR/Dockerfile-cnideploy docker
docker push $DOCKER_HUB_ID/cnideploy$DOCKER_TAG

docker build -t $DOCKER_HUB_ID/gbp-server$DOCKER_TAG -f $DOCKER_DIR/Dockerfile-gbpserver .
docker push $DOCKER_HUB_ID/gbp-server$DOCKER_TAG

echo "starting openvswitch build"
docker build -t $DOCKER_HUB_ID/openvswitch$DOCKER_TAG -f $DOCKER_DIR/Dockerfile-openvswitch .
docker push $DOCKER_HUB_ID/openvswitch$DOCKER_TAG

popd
