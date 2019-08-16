package jointlock_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestJointlock(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Jointlock Suite")
}
