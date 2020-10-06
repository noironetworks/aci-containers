#!/bin/sh
# usage: attach_bpf_ep.sh <vth>

/usr/local/bin/bpf/init.sh $1 /usr/local/bin/bpf/bpf_ep.o ingress ep-ingress
/usr/local/bin/bpf/init.sh $1 /usr/local/bin/bpf/bpf_ep.o egress ep-egress
