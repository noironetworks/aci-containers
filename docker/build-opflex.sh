#!/bin/bash

set -e
set -x

mkdir -p build/opflex/dist

pushd build/opflex

# Build OpFlex and OVS binaries
git clone https://git.opendaylight.org/gerrit/opflex.git --depth 1
pushd opflex/genie
mvn compile exec:java
popd
cp ../../docker/Dockerfile-opflex-build opflex
docker build -t noiro/opflex-build -f opflex/Dockerfile-opflex-build opflex
docker run noiro/opflex-build tar -c -C /usr/local \
       bin sbin share/openvswitch/scripts share/openvswitch/vswitch.ovsschema \
    | tar -x -C dist

# Build the minimal OpFlex container
cp ../../docker/Dockerfile-opflex dist
docker build -t noiro/opflex -f dist/Dockerfile-opflex dist

# Build the minimal OVS container
cp ../../docker/Dockerfile-openvswitch dist
docker build -t noiro/openvswitch -f dist/Dockerfile-openvswitch dist

popd
