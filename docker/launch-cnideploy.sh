#!/bin/sh

set -e
set -x

SYSCNIBIN=/mnt/cni-bin/cni/bin
CNIBIN=/opt/cni/bin

if [ -w /mnt/cni-bin ]; then
    # Install CNI plugin binaries
    mkdir -p ${SYSCNIBIN}
    cp ${CNIBIN}/loopback ${SYSCNIBIN}
fi
