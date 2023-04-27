#!/bin/bash
set -x

OPFLEX_BRANCH=kmr2
DOCKER_HUB_ID=quay.io/noirolabs
DOCKER_TAG=sumit-kmr2-test

SECOPT=
export SECOPT

DOCKER_DIR=docker/centos

OPFLEX_DIR=/tmp/opflex
export OPFLEX_DIR
git clone https://github.com/noironetworks/opflex.git -b $OPFLEX_BRANCH $OPFLEX_DIR

[ -z "$DOCKER_TAG" ] && DOCKER_TAG=
export DOCKER_HUB_ID
export DOCKER_TAG

set -Eeuxo pipefail

echo "starting opflex build"

docker build $SECOPT -t $DOCKER_HUB_ID/opflex-build-base:$DOCKER_TAG -f $DOCKER_DIR/Dockerfile-opflex-build-base . &> /tmp/opflex-build-base.log &
#docker push $DOCKER_HUB_ID/opflex-build-base$DOCKER_TAG
while [ ! -f  /tmp/opflex-build-base.log ]; do sleep 10; done
tail -f /tmp/opflex-build-base.log | awk 'NR%100-1==0' &

while [[ "$(docker images -q $DOCKER_HUB_ID/opflex-build-base:$DOCKER_TAG 2> /dev/null)" == "" ]]; do sleep 60; done

pushd $OPFLEX_DIR/genie
mvn compile exec:java
popd

pushd $OPFLEX_DIR
cd ..
tar cvfz opflex.tgz opflex
cp opflex.tgz opflex/
popd

docker build $SECOPT -t $DOCKER_HUB_ID/opflex-build:$DOCKER_TAG -f $DOCKER_DIR/Dockerfile-opflex-build $OPFLEX_DIR &> /tmp/opflex-build.log &
#docker push $DOCKER_HUB_ID/opflex-build$DOCKER_TAG
while [ ! -f  /tmp/opflex-build-base.log ]; do sleep 10; done
tail -f /tmp/opflex-build.log | awk 'NR%100-1==0' &

while [[ "$(docker images -q $DOCKER_HUB_ID/opflex-build:$DOCKER_TAG 2> /dev/null)" == "" ]]; do sleep 60; done

################## Copy everything from build into host ###############
rm -Rf build/opflex/dist
mkdir -p build/opflex/dist
mkdir -p build/opflex/dist/agent
mkdir -p build/opflex/dist/server
mkdir -p build/opflex/dist/usr/local/lib64
id=$(docker create $DOCKER_HUB_ID/opflex-build:$DOCKER_TAG)
docker cp -L $id:/usr/local/lib64 build/opflex/dist/usr/local
docker rm -v $id

docker run $DOCKER_HUB_ID/opflex-build:$DOCKER_TAG tar -c -C /usr/local \
    bin/opflex_agent bin/gbp_inspect bin/mcast_daemon bin/opflex_server \
    | tar -x -C build/opflex/dist
docker run -w /usr/local $DOCKER_HUB_ID/opflex-build:$DOCKER_TAG /bin/sh -c 'find lib \(\
         -name '\''libopflex*.so*'\'' -o \
         -name '\''libmodelgbp*so*'\'' -o \
         -name '\''libopenvswitch*so*'\'' -o \
         -name '\''libsflow*so*'\'' -o \
         -name '\''libprometheus-cpp-*so*'\'' -o \
         -name '\''libgrpc*so*'\'' -o \
         -name '\''libproto*so*'\'' -o \
         -name '\''libre2*so*'\'' -o \
         -name '\''libupb*so*'\'' -o \
         -name '\''libabsl*so*'\'' -o \
         -name '\''libssl*so*'\'' -o \
         -name '\''libcrypto*so*'\'' -o \
         -name '\''libaddress_sorting*so*'\'' -o \
         -name '\''libgpr*so*'\'' -o \
         -name '\''libofproto*so*'\'' \
         \) ! -name '\''*debug'\'' \
        | xargs tar -c ' \
    | tar -x -C build/opflex/dist
docker run -w /usr/local $DOCKER_HUB_ID/opflex-build:$DOCKER_TAG /bin/sh -c 'find lib \(\
         -name '\''libopflex*.so*'\'' -o \
         -name '\''libmodelgbp*so*'\'' -o \
         -name '\''libopenvswitch*so*'\'' -o \
         -name '\''libsflow*so*'\'' -o \
         -name '\''libprometheus-cpp-*so*'\'' -o \
         -name '\''libofproto*so*'\'' \
         \) ! -name '\''*debug'\'' \
        | xargs tar -c ' \
    | tar -x -C build/opflex/dist/agent
docker run -w /usr/local $DOCKER_HUB_ID/opflex-build:$DOCKER_TAG /bin/sh -c 'find lib \(\
         -name '\''libopflex*.so*'\'' -o \
         -name '\''libmodelgbp*so*'\'' -o \
         -name '\''libprometheus-cpp-*so*'\'' -o \
         -name '\''libgrpc*so*'\'' -o \
         -name '\''libproto*so*'\'' -o \
         -name '\''libre2*so*'\'' -o \
         -name '\''libupb*so*'\'' -o \
         -name '\''libabsl*so*'\'' -o \
         -name '\''libssl*so*'\'' -o \
         -name '\''libcrypto*so*'\'' -o \
         -name '\''libaddress_sorting*so*'\'' -o \
         -name '\''libgpr*so*'\'' \
         \) ! -name '\''*debug'\'' \
        | xargs tar -c ' \
    | tar -x -C build/opflex/dist/server
docker run -w /usr/local $DOCKER_HUB_ID/opflex-build:$DOCKER_TAG /bin/sh -c \
	'find lib bin -name '\''*.debug'\'' | xargs tar -cz' \
	 > opflex-debuginfo.tar.gz
cp $DOCKER_DIR/launch-opflexagent.sh build/opflex/dist/bin/
cp $DOCKER_DIR/launch-mcastdaemon.sh build/opflex/dist/bin/
cp $DOCKER_DIR/launch-opflexserver.sh build/opflex/dist/bin/
cp $DOCKER_DIR/Dockerfile-opflex build/opflex/dist/
cp $DOCKER_DIR/Dockerfile-opflexserver build/opflex/dist/
cp $DOCKER_DIR/Dockerfile-opflex-distro build/opflex/dist/

#######################################################################################
docker build -t quay.io/noirolabs/opflex:sumit-kmr2-test -f ./build/opflex/dist/Dockerfile-opflex build/opflex/dist
docker push quay.io/noirolabs/opflex:sumit-kmr2-test
