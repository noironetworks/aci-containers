/*
**
Copyright 2019 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package gbpserver

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	status "google.golang.org/grpc/status"
)

func TestUnimplementedGBPServer_ListObjects(t *testing.T) {
	server := UnimplementedGBPServer{}
	req := &Version{}
	stream := &mockGBPListObjectsServer{}

	err := server.ListObjects(req, stream)
	if err == nil {
		t.Errorf("Expected error, got nil")
	}

	status, ok := status.FromError(err)
	if !ok {
		t.Errorf("Expected gRPC status error, got %v", err)
	}

	if status.Code() != codes.Unimplemented {
		t.Errorf("Expected error code %v, got %v", codes.Unimplemented, status.Code())
	}

	expectedMsg := "method ListObjects not implemented"
	if status.Message() != expectedMsg {
		t.Errorf("Expected error message %q, got %q", expectedMsg, status.Message())
	}
}

type mockGBPListObjectsServer struct {
	grpc.ServerStream
}

func (m *mockGBPListObjectsServer) Send(*GBPOperation) error {
	return nil
}

func (m *mockGBPListObjectsServer) Context() context.Context {
	return context.Background()
}

func (m *mockGBPListObjectsServer) SendHeader(metadata.MD) error {
	return nil
}

func (m *mockGBPListObjectsServer) SetHeader(metadata.MD) error {
	return nil
}

func (m *mockGBPListObjectsServer) SetTrailer(metadata.MD) {
}

func (m *mockGBPListObjectsServer) Method() string {
	return ""
}

func (m *mockGBPListObjectsServer) Peer() string {
	return ""
}

func (m *mockGBPListObjectsServer) AuthInfo() credentials.AuthInfo {
	return nil
}

func TestUnimplementedGBPServer_ListVTEPs(t *testing.T) {
	server := UnimplementedGBPServer{}
	req := &EmptyMsg{}
	expectedErr := status.Errorf(codes.Unimplemented, "method ListVTEPs not implemented")

	_, err := server.ListVTEPs(context.Background(), req)
	if err == nil {
		t.Errorf("Expected error, got nil")
	}

	if err.Error() != expectedErr.Error() {
		t.Errorf("Expected error %q, got %q", expectedErr.Error(), err.Error())
	}
}
func TestUnimplementedGBPServer_GetSnapShot(t *testing.T) {
	server := UnimplementedGBPServer{}
	req := &VTEP{}
	expectedErr := status.Errorf(codes.Unimplemented, "method GetSnapShot not implemented")

	_, err := server.GetSnapShot(context.Background(), req)
	if err == nil {
		t.Errorf("Expected error, got nil")
	}

	if err.Error() != expectedErr.Error() {
		t.Errorf("Expected error %q, got %q", expectedErr.Error(), err.Error())
	}
}
func TestUnimplementedGBPServer_MustEmbedUnimplementedGBPServer(t *testing.T) {
	server := UnimplementedGBPServer{}
	server.mustEmbedUnimplementedGBPServer()
}
