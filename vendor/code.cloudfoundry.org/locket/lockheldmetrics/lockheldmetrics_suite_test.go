package lockheldmetrics_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestLockheldmetrics(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Lockheldmetrics Suite")
}
