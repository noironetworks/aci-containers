#!/bin/bash
# Build opflex and aci-containers private images in non jenkins environment
# 1. go get github.com/noironetworks/aci-containers
# 2. mkdir -p $HOME/work && cd $HOME/work
# 3. git clone https://github.com/noironetworks/opflex opflex-noiro
# 4. Modify docker/Dockerfile-* and Makefile to reflect DOCKER_HUB_ID
# 5. docker login as DOCKER_HUB_ID
# usage: build.sh <docker-user> :<tag>
# example: ./build-priv.sh challa :demo
set -x

DOCKER_HUB_ID=$1
DOCKER_TAG=$2

[ -z "$GOPATH" ] && GOPATH=$HOME/go
export GOPATH
ACICONTAINERS_DIR=.

[ -z "$OPFLEX_DIR" ] && OPFLEX_DIR=$HOME/work/opflex-noiro
export OPFLEX_DIR

[ -z "$DOCKER_TAG" ] && DOCKER_TAG=
export DOCKER_HUB_ID
export DOCKER_TAG

set -Eeuxo pipefail

echo "starting opflex build"

pushd $ACICONTAINERS_DIR
rm -Rf build
docker build -t $DOCKER_HUB_ID/opflex-build-base$DOCKER_TAG -f docker/Dockerfile-opflex-build-base docker
docker push $DOCKER_HUB_ID/opflex-build-base$DOCKER_TAG

pushd $OPFLEX_DIR/genie
mvn compile exec:java
popd
docker build -t $DOCKER_HUB_ID/opflex-build$DOCKER_TAG -f docker/Dockerfile-opflex-build $OPFLEX_DIR
docker push $DOCKER_HUB_ID/opflex-build$DOCKER_TAG

mkdir -p build/opflex/dist
docker run $DOCKER_HUB_ID/opflex-build$DOCKER_TAG tar -c -C /usr/local \
	bin/opflex_agent bin/gbp_inspect bin/mcast_daemon bin/mock_server \
	| tar -x -C build/opflex/dist
docker run -w /usr/local $DOCKER_HUB_ID/opflex-build$DOCKER_TAG /bin/sh -c 'find lib \(\
	 -name '\''libopflex*.so*'\'' -o \
	 -name '\''libmodelgbp*so*'\'' -o \
	 -name '\''libopenvswitch*so*'\'' -o \
	  -name '\''libsflow*so*'\'' -o \
	  -name '\''libofproto*so*'\'' \
           \) ! -name '\''*debug'\'' \
           | xargs tar -c ' \
	  | tar -x -C build/opflex/dist
docker run -w /usr $DOCKER_HUB_ID/opflex-build$DOCKER_TAG /bin/sh -c 'find lib \(\
         -name '\''libexecinfo.so.*'\'' -o \
          \) ! -name '\''*debug'\'' \
         | xargs tar -c ' \
        | tar -x -C build/opflex/dist
docker run -w /usr/local $DOCKER_HUB_ID/opflex-build$DOCKER_TAG /bin/sh -c \
	'find lib bin -name '\''*.debug'\'' | xargs tar -cz' \
	 > opflex-debuginfo.tar.gz
cp docker/launch-opflexagent.sh build/opflex/dist/bin/
cp docker/launch-mcastdaemon.sh build/opflex/dist/bin/
cp docker/launch-opflexserver.sh build/opflex/dist/bin/
cp docker/Dockerfile-opflex build/opflex/dist/
cp docker/Dockerfile-opflexserver build/opflex/dist/

docker build -t $DOCKER_HUB_ID/opflex$DOCKER_TAG -f ./build/opflex/dist/Dockerfile-opflex build/opflex/dist
docker push $DOCKER_HUB_ID/opflex$DOCKER_TAG
docker build -t $DOCKER_HUB_ID/opflex-server$DOCKER_TAG -f ./build/opflex/dist/Dockerfile-opflexserver build/opflex/dist
docker push $DOCKER_HUB_ID/opflex-server$DOCKER_TAG

echo "starting aci-containers build"
make all-static

docker build -t $DOCKER_HUB_ID/aci-containers-controller$DOCKER_TAG -f docker/Dockerfile-controller .
docker push $DOCKER_HUB_ID/aci-containers-controller$DOCKER_TAG

docker build -t $DOCKER_HUB_ID/aci-containers-host$DOCKER_TAG -f docker/Dockerfile-host .
docker push $DOCKER_HUB_ID/aci-containers-host$DOCKER_TAG

docker build -t $DOCKER_HUB_ID/cnideploy$DOCKER_TAG -f docker/Dockerfile-cnideploy docker
docker push $DOCKER_HUB_ID/cnideploy$DOCKER_TAG

docker build -t $DOCKER_HUB_ID/gbp-server$DOCKER_TAG -f docker/Dockerfile-gbpserver .
docker push $DOCKER_HUB_ID/gbp-server$DOCKER_TAG

echo "starting openvswitch build"
docker build -t $DOCKER_HUB_ID/openvswitch$DOCKER_TAG -f docker/Dockerfile-openvswitch .
docker push $DOCKER_HUB_ID/openvswitchi$DOCKER_TAG

popd
