#!/bin/sh

set -e
set -x

OVSCTL=/usr/share/openvswitch/scripts/ovs-ctl
export OVS_RUNDIR=/usr/local/var/run/openvswitch
exec ${OVSCTL} status
