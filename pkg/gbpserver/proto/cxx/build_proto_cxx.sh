#!/bin/bash

docker run --rm -m 16g -v ${PWD}/..:/go/src/github.com/noironetworks/aci-containers/pkg/gbpserver/proto -w /go/src/github.com/noironetworks/aci-containers/pkg/gbpserver/proto --network=host -it grpc/cxx protoc -I . --grpc_out=./cxx --plugin=protoc-gen-grpc=/usr/local/bin/grpc_cpp_plugin ./gbp.proto
docker run --rm -m 16g -v ${PWD}/..:/go/src/github.com/noironetworks/aci-containers/pkg/gbpserver/proto -w /go/src/github.com/noironetworks/aci-containers/pkg/gbpserver/proto --network=host -it grpc/cxx protoc -I . --cpp_out=./cxx ./gbp.proto
