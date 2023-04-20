#!/bin/bash
# usage: build_opflex.sh docker-id :tag
# expects opflex.tgz in $OPFLEX_DIR
# example: ./build-priv.sh challa :demo
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
  echo "usage: build_opflex.sh docker-id :tag"
  exit -1
fi

DOCKER_DIR=.

# Modify docker/Dockerfile-opflex-build to reflect DOCKER_HUB_ID and  DOCKER_TAG
sed -i -e "s/FROM noiro\/opflex-build-base.*$/FROM $DOCKER_HUB_ID\/opflex-build-base$DOCKER_TAG/g" \
           $DOCKER_DIR/Dockerfile-opflex-build


[ -z "$OPFLEX_DIR" ] && OPFLEX_DIR=/root/mchalla/opflex
export OPFLEX_DIR

[ -z "$DOCKER_TAG" ] && DOCKER_TAG=
export DOCKER_HUB_ID
export DOCKER_TAG

set -Eeuxo pipefail

echo "starting opflex build"

docker build $SECOPT $BUILDARG -t $DOCKER_HUB_ID/opflex-build-base$DOCKER_TAG -f $DOCKER_DIR/Dockerfile-opflex-build-base .
#docker push $DOCKER_HUB_ID/opflex-build-base$DOCKER_TAG

pushd $OPFLEX_DIR/genie
mvn compile exec:java
popd
docker build $SECOPT $BUILDARG -t $DOCKER_HUB_ID/opflex-build$DOCKER_TAG -f $DOCKER_DIR/Dockerfile-opflex-build $OPFLEX_DIR
#docker push $DOCKER_HUB_ID/opflex-build$DOCKER_TAG

################## Copy everything from build into host ###############
rm -Rf build/opflex/dist
mkdir -p build/opflex/dist
mkdir -p build/opflex/dist/agent
mkdir -p build/opflex/dist/server
mkdir -p build/opflex/dist/usr/local/lib64
id=$(docker create $DOCKER_HUB_ID/opflex-build$DOCKER_TAG)
docker cp -L $id:/usr/local/lib64 build/opflex/dist/usr/local
docker rm -v $id

docker run $DOCKER_HUB_ID/opflex-build$DOCKER_TAG tar -c -C /usr/local \
    bin/opflex_agent bin/gbp_inspect bin/mcast_daemon bin/opflex_server \
    | tar -x -C build/opflex/dist
docker run -w /usr/local $DOCKER_HUB_ID/opflex-build$DOCKER_TAG /bin/sh -c 'find lib \(\
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
docker run -w /usr/local $DOCKER_HUB_ID/opflex-build$DOCKER_TAG /bin/sh -c 'find lib \(\
         -name '\''libopflex*.so*'\'' -o \
         -name '\''libmodelgbp*so*'\'' -o \
         -name '\''libopenvswitch*so*'\'' -o \
         -name '\''libsflow*so*'\'' -o \
         -name '\''libprometheus-cpp-*so*'\'' -o \
         -name '\''libofproto*so*'\'' \
         \) ! -name '\''*debug'\'' \
        | xargs tar -c ' \
    | tar -x -C build/opflex/dist/agent
docker run -w /usr/local $DOCKER_HUB_ID/opflex-build$DOCKER_TAG /bin/sh -c 'find lib \(\
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
docker run -w /usr/local $DOCKER_HUB_ID/opflex-build$DOCKER_TAG /bin/sh -c \
	'find lib bin -name '\''*.debug'\'' | xargs tar -cz' \
	 > opflex-debuginfo.tar.gz
cp $DOCKER_DIR/launch-opflexagent.sh build/opflex/dist/bin/
cp $DOCKER_DIR/launch-mcastdaemon.sh build/opflex/dist/bin/
cp $DOCKER_DIR/launch-opflexserver.sh build/opflex/dist/bin/
cp $DOCKER_DIR/Dockerfile-opflex build/opflex/dist/
cp $DOCKER_DIR/Dockerfile-opflexserver build/opflex/dist/
cp $DOCKER_DIR/Dockerfile-opflex-distro build/opflex/dist/

#######################################################################################
docker build $BUILDARG -t $DOCKER_HUB_ID/opflex$DOCKER_TAG -f ./build/opflex/dist/Dockerfile-opflex build/opflex/dist
docker push $DOCKER_HUB_ID/opflex$DOCKER_TAG
docker build $BUILDARG -t $DOCKER_HUB_ID/opflexserver$DOCKER_TAG -f ./build/opflex/dist/Dockerfile-opflexserver build/opflex/dist
docker push $DOCKER_HUB_ID/opflexserver$DOCKER_TAG
docker build $BUILDARG -t $DOCKER_HUB_ID/opflex-distro$DOCKER_TAG -f ./build/opflex/dist/Dockerfile-opflex-distro build/opflex/dist
docker push $DOCKER_HUB_ID/opflex-distro$DOCKER_TAG
