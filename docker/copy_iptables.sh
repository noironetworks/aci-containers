#!/bin/bash

# This script is intended to be used from jenkins script or
# from build_priv.sh, it would copy iptables binaries and
# libraries from opflex-build-base into dist-static to be
# used by consumers of iptables like the host agent container
# use copy_iptables.sh <opflex-build-base-image> <target-dir>

set -x

BASE_IMAGE=$1
TARGET_DIR=$2

parent_path="$( dirname "${BASH_SOURCE[0]}" )"
mkdir -p ${TARGET_DIR}

docker run -w /usr/sbin ${BASE_IMAGE} tar -cz -C /usr/sbin \
  nfnl_osf xtables-legacy-multi xtables-nft-multi iptables-apply \
  > ${TARGET_DIR}/iptables-bin.tar.gz

docker run -w /lib64 ${BASE_IMAGE} /bin/sh -c 'find . \(\
 -name '\''libxtables*.so*'\'' -o \
 -name '\''libip6tc*.so*'\'' -o \
 -name '\''libip4tc*.so*'\'' \
\)  \
| xargs tar -cz ' > ${TARGET_DIR}/iptables-libs.tar.gz

cp ${parent_path}/iptables-wrapper-installer.sh ${TARGET_DIR}
