[![Build Status](https://travis-ci.com/noironetworks/aci-containers.svg?branch=master)](https://travis-ci.com/noironetworks/aci-containers)
[![Go Report Card](https://goreportcard.com/badge/github.com/noironetworks/aci-containers)](https://goreportcard.com/report/github.com/noironetworks/aci-containers)
[![image](https://coveralls.io/repos/github/noironetworks/aci-containers/badge.svg?branch=master)](https://coveralls.io/github/noironetworks/aci-containers?branch=master)

## ACI CNI Plugin

The Cisco Application Centric Infrastructure (ACI) CNI plugin brings the
ACI Networking and Policy model to Kubernetes clusters that reside
on-prem or in the cloud. It is fully open source and relies on the
[Opflex Protocol](https://github.com/noironetworks/opflex) to program
Open vSwitch instances running on the Kubernetes nodes. It provides IP
address management, L2/L3 networking, load balancing, and security
functions for container workloads.
