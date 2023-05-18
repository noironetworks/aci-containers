#!/bin/sh

set -e
set -x

PREFIX=/usr/local
OVSCTL=$PREFIX/share/openvswitch/scripts/ovs-ctl
export OVS_RUNDIR=$PREFIX/var/run/openvswitch
export LD_LIBRARY_PATH=$PREFIX/lib:$LD_LIBRARY_PATH
exec ${OVSCTL} status
