#!/bin/bash
# usage: ./build_openvswitch.sh <docker-reg> <docker-tag> <docker-build-args>
set -x

DOCKER_HUB_ID=$1
DOCKER_TAG=$2
BUILDARG=$3
[ -z "$DOCKER_HUB_ID" ] && DOCKER_HUB_ID=
[ -z "$DOCKER_TAG" ] && DOCKER_TAG=
[ -z "$BUILDARG" ] && BUILDARG=
export DOCKER_HUB_ID
export DOCKER_TAG
export BUILDARG

SECOPT=
export SECOPT

DOCKER_DIR=docker/travis

set -Eeuxo pipefail

#make -C . vendor dist-static/ovsresync

echo "starting ovs build"
echo "building base image"
rm -Rf build/openvswitch
mkdir -p build/openvswitch
cp $DOCKER_DIR/Dockerfile-openvswitch-base build/openvswitch
if [[ "${GITHUB_ACTIONS:-false}" == "true" ]]; then
    ovs_build_log="${CI_ARTIFACT_DIR:-/tmp}/openvswitch-base.log"
    mkdir -p "$(dirname "${ovs_build_log}")"
    rm -f "${ovs_build_log}"

    docker build $BUILDARG \
        -t "$DOCKER_HUB_ID/openvswitch-base:$DOCKER_TAG" \
        -f ./build/openvswitch/Dockerfile-openvswitch-base \
        build/openvswitch >"${ovs_build_log}" 2>&1 &
    ovs_build_pid=$!

    cleanup_ovs_build() {
        if kill -0 "${ovs_build_pid}" 2>/dev/null; then
            kill "${ovs_build_pid}" 2>/dev/null || true
            wait "${ovs_build_pid}" 2>/dev/null || true
        fi
    }
    trap cleanup_ovs_build EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    while kill -0 "${ovs_build_pid}" 2>/dev/null; do
        echo "Open vSwitch base build is still running ($(date -u +%FT%TZ)); full output is saved as an artifact."
        sleep 60
    done

    set +e
    wait "${ovs_build_pid}"
    ovs_build_status=$?
    set -e
    trap - EXIT INT TERM

    if [[ "${ovs_build_status}" -ne 0 ]]; then
        echo "Open vSwitch base build failed; showing the final 200 log lines." >&2
        tail -200 "${ovs_build_log}" >&2
        exit "${ovs_build_status}"
    fi

    tail -25 "${ovs_build_log}"
else
    docker build $BUILDARG -t $DOCKER_HUB_ID/openvswitch-base:$DOCKER_TAG -f ./build/openvswitch/Dockerfile-openvswitch-base build/openvswitch &> /tmp/openvswitch-base.log &
    while [ ! -f  /tmp/openvswitch-base.log ]; do sleep 10; done
    tail -f /tmp/openvswitch-base.log | awk 'NR%100-1==0' &
    while [[ "$(pgrep -x 'docker' 2> /dev/null)" != '' ]]; do sleep 60; done

    tail -25 /tmp/openvswitch-base.log
fi

echo "copying intermediate binaries and libs"
rm -Rf build/openvswitch/dist
mkdir -p build/openvswitch/dist/usr/local
id=$(docker create $DOCKER_HUB_ID/openvswitch-base:$DOCKER_TAG)
docker cp -L $id:/usr/local/lib build/openvswitch/dist/usr/local
docker cp -L $id:/usr/local/bin build/openvswitch/dist/usr/local
docker cp -L $id:/usr/local/sbin build/openvswitch/dist/usr/local
docker cp -L $id:/usr/local/share build/openvswitch/dist/usr/local
docker rm -v $id
cp $DOCKER_DIR/launch-ovs.sh build/openvswitch/dist/usr/local/bin
cp $DOCKER_DIR/liveness-ovs.sh build/openvswitch/dist/usr/local/bin
mkdir build/openvswitch/dist/licenses
cp $DOCKER_DIR/../licenses/* build/openvswitch/dist/licenses
cp dist-static/ovsresync build/openvswitch/dist/usr/local/bin

echo "building final image"
cp $DOCKER_DIR/Dockerfile-openvswitch build/openvswitch
docker build $BUILDARG -t $DOCKER_HUB_ID/openvswitch:$DOCKER_TAG -f ./build/openvswitch/Dockerfile-openvswitch build/openvswitch/dist
