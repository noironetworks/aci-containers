package handlers_test

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"code.cloudfoundry.org/bbs/db/sqldb/helpers"
	"code.cloudfoundry.org/bbs/db/sqldb/helpers/monitor"
	"code.cloudfoundry.org/bbs/guidprovider"
	"code.cloudfoundry.org/bbs/test_helpers"
	"code.cloudfoundry.org/bbs/test_helpers/sqlrunner"
	"code.cloudfoundry.org/lager/lagertest"
	"code.cloudfoundry.org/locket/db"
	"code.cloudfoundry.org/locket/expiration/expirationfakes"
	"code.cloudfoundry.org/locket/handlers"
	"code.cloudfoundry.org/locket/metrics/helpers/helpersfakes"
	"code.cloudfoundry.org/locket/models"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"
)

var _ = Describe("LocketHandler", func() {
	var (
		sqlProcess         ifrit.Process
		sqlRunner          sqlrunner.SQLRunner
		lockDB             *db.SQLDB
		sqlConn            *sql.DB
		fakeLockPick       *expirationfakes.FakeLockPick
		logger             *lagertest.TestLogger
		locketHandler      models.LocketServer
		resource           *models.Resource
		exitCh             chan struct{}
		fakeRequestMetrics *helpersfakes.FakeRequestMetrics
	)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("locket-handler")

		dbName := fmt.Sprintf("diego_%d", GinkgoParallelNode())
		sqlRunner = test_helpers.NewSQLRunner(dbName)
		sqlProcess = ginkgomon.Invoke(sqlRunner)

		var err error
		sqlConn, err = sql.Open(sqlRunner.DriverName(), sqlRunner.ConnectionString())
		Expect(err).NotTo(HaveOccurred())

		dbMonitor := monitor.New()
		monitoredDB := helpers.NewMonitoredDB(sqlConn, dbMonitor)

		lockDB = db.NewSQLDB(
			monitoredDB,
			sqlRunner.DriverName(),
			guidprovider.DefaultGuidProvider,
		)
		err = lockDB.CreateLockTable(context.Background(), logger)
		Expect(err).NotTo(HaveOccurred())

		fakeLockPick = &expirationfakes.FakeLockPick{}
		fakeRequestMetrics = &helpersfakes.FakeRequestMetrics{}

		exitCh = make(chan struct{}, 1)

		resource = &models.Resource{
			Key:   "test",
			Value: "test-value",
			Owner: "myself",
			Type:  "lock",
		}

		locketHandler = handlers.NewLocketHandler(
			logger,
			lockDB,
			fakeLockPick,
			fakeRequestMetrics,
			exitCh,
		)
	})

	AfterEach(func() {
		Expect(sqlConn.Close()).To(Succeed())
		ginkgomon.Kill(sqlProcess)
	})

	Context("when request is cancelled", func() {
		BeforeEach(func() {
			sqlConn.SetMaxOpenConns(1)
			go func() {
				defer GinkgoRecover()
				var sleepQuery string
				if test_helpers.UseMySQL() {
					sleepQuery = "select sleep(60);"
				} else if test_helpers.UsePostgres() {
					sleepQuery = `--pg_sleep_query_context_test
            select pg_sleep(60);`
				} else {
					Fail("unknown db driver")
				}
				sqlConn.Exec(sleepQuery)
			}()
		})

		AfterEach(func() {
			sqlConn.SetMaxOpenConns(0)
			if test_helpers.UsePostgres() {
				// cancel the sleep query in postgres, since it does not allow to drop the database
				_, err := sqlConn.Exec(`SELECT pg_cancel_backend(pid)
				FROM pg_stat_activity
				WHERE state = 'active'
				AND query LIKE '--pg_sleep_query_context_test%'`)
				Expect(err).NotTo(HaveOccurred())
			}
		})

		It("cancels the database request", func() {
			ctxWithCancel, cancelFn := context.WithCancel(context.Background())

			finishedRequest := make(chan struct{}, 1)
			go func() {
				defer GinkgoRecover()
				_, err := locketHandler.Lock(ctxWithCancel, &models.LockRequest{
					Resource:     resource,
					TtlInSeconds: 10,
				})
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError(context.Canceled))
				close(finishedRequest)
			}()

			Eventually(logger).Should(gbytes.Say("started"))

			cancelFn()

			Eventually(finishedRequest, 5*time.Second).Should(BeClosed())
		})
	})
})
