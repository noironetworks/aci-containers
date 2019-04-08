package grpcserver_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestGrpcserver(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Grpcserver Suite")
}
