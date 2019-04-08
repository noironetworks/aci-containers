package locket_test

import (
	"code.cloudfoundry.org/consuladapter/consulrunner"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/config"
	. "github.com/onsi/gomega"

	"testing"
)

var (
	consulStartingPort int
	consulRunner       *consulrunner.ClusterRunner
)

const (
	defaultScheme = "http"
)

func TestLocket(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Locket Suite")
}

var _ = BeforeSuite(func() {
	consulStartingPort = 5001 + config.GinkgoConfig.ParallelNode*consulrunner.PortOffsetLength
	consulRunner = consulrunner.NewClusterRunner(
		consulrunner.ClusterRunnerConfig{
			StartingPort: consulStartingPort,
			NumNodes:     1,
			Scheme:       defaultScheme,
		},
	)

	consulRunner.Start()
	consulRunner.WaitUntilReady()
})

var _ = BeforeEach(func() {
	consulRunner.Reset()
})

var _ = AfterSuite(func() {
	consulRunner.Stop()
})
