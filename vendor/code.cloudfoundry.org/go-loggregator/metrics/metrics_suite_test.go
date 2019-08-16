package metrics_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"log"

	"testing"
)

func TestMetrics(t *testing.T) {
	log.SetOutput(GinkgoWriter)
	RegisterFailHandler(Fail)
	RunSpecs(t, "Metrics Suite")
}
