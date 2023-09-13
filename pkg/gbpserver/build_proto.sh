#!/bin/bash

docker run --rm -m 16g -v "${PWD}":/go/src/github.com/noironetworks/aci-containers/pkg/gbpserver/proto -w /go/src/github.com/noironetworks/aci-containers/pkg/gbpserver/proto --network=host -it golang:1.20.7 /bin/bash -c "apt update && apt install -y protobuf-compiler && go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.31.0 && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0 && protoc -I proto/ proto/gbp.proto --go_out=. --go-grpc_out=. --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative"
