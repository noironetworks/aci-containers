package main_test

import (
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"google.golang.org/grpc/grpclog"

	"code.cloudfoundry.org/bbs/test_helpers"
	"code.cloudfoundry.org/bbs/test_helpers/sqlrunner"
	"code.cloudfoundry.org/consuladapter/consulrunner"
	"code.cloudfoundry.org/inigo/helpers/portauthority"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"

	"testing"
)

var (
	locketBinPath string

	sqlProcess   ifrit.Process
	sqlRunner    sqlrunner.SQLRunner
	consulRunner *consulrunner.ClusterRunner

	TruncateTableList = []string{"locks"}
	portAllocator     portauthority.PortAllocator
)

func TestLocket(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Locket Suite")
}

var _ = SynchronizedBeforeSuite(
	func() []byte {
		locketBinPathData, err := gexec.Build("code.cloudfoundry.org/locket/cmd/locket", "-race")
		Expect(err).NotTo(HaveOccurred())
		return []byte(locketBinPathData)
	},
	func(locketBinPathData []byte) {
		node := GinkgoParallelNode()
		startPort := 1050 * node
		portRange := 1000
		endPort := startPort + portRange

		var err error
		portAllocator, err = portauthority.New(startPort, endPort)
		Expect(err).NotTo(HaveOccurred())

		grpclog.SetLogger(log.New(ioutil.Discard, "", 0))

		locketBinPath = string(locketBinPathData)
		SetDefaultEventuallyTimeout(15 * time.Second)

		dbName := fmt.Sprintf("diego_%d", GinkgoParallelNode())
		sqlRunner = test_helpers.NewSQLRunner(dbName)
		sqlProcess = ginkgomon.Invoke(sqlRunner)

		port, err := portAllocator.ClaimPorts(consulrunner.PortOffsetLength)
		Expect(err).NotTo(HaveOccurred())

		consulRunner = consulrunner.NewClusterRunner(
			consulrunner.ClusterRunnerConfig{
				StartingPort: int(port),
				NumNodes:     1,
				Scheme:       "http",
			},
		)
		consulRunner.Start()
	},
)

var _ = BeforeEach(func() {
	consulRunner.WaitUntilReady()
	consulRunner.Reset()
})

var _ = SynchronizedAfterSuite(func() {
	if consulRunner != nil {
		consulRunner.Stop()
	}
	ginkgomon.Kill(sqlProcess)
}, func() {
	gexec.CleanupBuildArtifacts()
})
