#!/bin/bash
# Build opflex and aci-containers private images in non jenkins environment
# 1. go get github.com/noironetworks/aci-containers
# 2. mkdir -p $HOME/work && cd $HOME/work
# 3. git clone https://github.com/noironetworks/opflex opflex-noiro
# 4. Modify docker/Dockerfile-* and Makefile to reflect DOCKER_USER
# 5. docker login as DOCKER_USER
# usage: build.sh <opflex-dir> <aci-containers-dir> <docker-user>
# example: ./build-priv.sh challa

DOCKER_USER=$1

[ -z "$GOPATH" ] && GOPATH=$HOME/go
export GOPATH
ACICONTAINERS_DIR=$GOPATH/src/github.com/noironetworks/aci-containers

[ -z "$OPFLEX_DIR" ] && OPFLEX_DIR=$HOME/work/opflex-noiro
export OPFLEX_DIR

set -Eeuxo pipefail

echo "starting opflex build"

pushd $ACICONTAINERS_DIR
rm -Rf build
make container-opflex-build-base
docker build -t $DOCKER_USER/opflex-build-base -f docker/Dockerfile-opflex-build-base-debug docker
docker push $DOCKER_USER/opflex-build-base

pushd $OPFLEX_DIR/genie
mvn compile exec:java
popd
docker build -t $DOCKER_USER/opflex-build -f docker/Dockerfile-opflex-build $OPFLEX_DIR
docker push $DOCKER_USER/opflex-build

mkdir -p build/opflex/dist
docker run $DOCKER_USER/opflex-build tar -c -C /usr/local \
	bin/opflex_agent bin/gbp_inspect bin/mcast_daemon bin/mock_server \
	| tar -x -C build/opflex/dist
docker run -w /usr/local $DOCKER_USER/opflex-build /bin/sh -c 'find lib \(\
	 -name '\''libopflex*.so*'\'' -o \
	 -name '\''libmodelgbp*so*'\'' -o \
	 -name '\''libopenvswitch*so*'\'' -o \
	  -name '\''libsflow*so*'\'' -o \
	  -name '\''libofproto*so*'\'' \
           \) ! -name '\''*debug'\'' \
           | xargs tar -c ' \
	  | tar -x -C build/opflex/dist
docker run -w /usr $DOCKER_USER/opflex-build /bin/sh -c 'find lib \(\
         -name '\''libexecinfo.so.*'\'' -o \
          \) ! -name '\''*debug'\'' \
         | xargs tar -c ' \
        | tar -x -C build/opflex/dist
docker run -w /usr/local $DOCKER_USER/opflex-build /bin/sh -c \
	'find lib bin -name '\''*.debug'\'' | xargs tar -cz' \
	 > opflex-debuginfo.tar.gz
cp docker/launch-opflexagent.sh build/opflex/dist/bin/
cp docker/launch-mcastdaemon.sh build/opflex/dist/bin/
cp docker/launch-opflexserver.sh build/opflex/dist/bin/
cp docker/Dockerfile-opflex build/opflex/dist/
cp docker/Dockerfile-opflexserver build/opflex/dist/

docker build -t $DOCKER_USER/opflex -f ./build/opflex/dist/Dockerfile-opflex build/opflex/dist
docker push $DOCKER_USER/opflex
docker build -t $DOCKER_USER/opflexserver -f ./build/opflex/dist/Dockerfile-opflexserver build/opflex/dist
docker push $DOCKER_USER/opflexserver

echo "starting aci-containers build"
make all-static

docker build -t $DOCKER_USER/aci-containers-controller -f docker/Dockerfile-controller .
docker push $DOCKER_USER/aci-containers-controller

docker build -t $DOCKER_USER/aci-containers-host -f docker/Dockerfile-host .
docker push $DOCKER_USER/aci-containers-host

docker build -t $DOCKER_USER/cnideploy -f docker/Dockerfile-cnideploy docker
docker push $DOCKER_USER/cnideploy

echo "starting openvswitch build"
docker build -t $DOCKER_USER/openvswitch -f docker/Dockerfile-openvswitch .
docker push $DOCKER_USER/openvswitch

popd
