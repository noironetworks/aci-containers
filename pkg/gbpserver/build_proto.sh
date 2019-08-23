#!/bin/bash
docker run --rm -m 16g -v ${PWD}:/go/src/github.com/noironetworks/aci-containers/pkg/gbpserver/proto -w /go/src/github.com/noironetworks/aci-containers/pkg/gbpserver/proto --network=host -it grpc/go protoc -I proto/ proto/gbp.proto --go_out=plugins=grpc:.
