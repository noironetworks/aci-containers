#!/bin/sh
kubectl get nodes -o wide | grep Ready | grep -v NotReady | awk '{print $6}'
