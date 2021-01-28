#!/bin/sh
# usage: attach_bpf_ep.sh <ifc> <ingress|egress> <section>

/usr/local/bin/bpf/init.sh $1 /usr/local/bin/bpf/bpf_ep.o $2 $3
