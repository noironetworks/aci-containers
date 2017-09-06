#!/bin/bash

set -e
set -x

mkdir -p build/opflex/dist

pushd build/opflex

# Build OpFlex and OVS binaries
if [ -d opflex ]; then
    pushd opflex
    git pull
    popd
else
    git clone https://git.opendaylight.org/gerrit/opflex.git --depth 1
fi
pushd opflex/genie
mvn compile exec:java
popd
cp ../../docker/Dockerfile-opflex-build opflex
docker build ${DOCKER_BUILD_ARGS} --build-arg make_args="${MAKE_ARGS}" -t noiro/opflex-build -f opflex/Dockerfile-opflex-build opflex
docker run noiro/opflex-build tar -c -C /usr/local \
       bin/agent_ovs bin/gbp_inspect bin/mcast_daemon \
    | tar -x -C dist
docker run noiro/opflex-build tar -zc -C /usr/local \
       bin/agent_ovs.debug bin/gbp_inspect.debug bin/mcast_daemon.debug \
    > debuginfo.tar.gz
cp ../../docker/launch-opflexagent.sh dist/bin/
cp ../../docker/launch-mcastdaemon.sh dist/bin/
cp ../../docker/launch-ovs.sh dist/bin/

# Build the minimal OpFlex container
cp ../../docker/Dockerfile-opflex dist
docker build ${DOCKER_BUILD_ARGS} -t noiro/opflex -f dist/Dockerfile-opflex dist

popd
