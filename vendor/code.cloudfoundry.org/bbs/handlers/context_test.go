package handlers_test

import (
	"context"
	"database/sql"
	"fmt"
	"net/http/httptest"
	"time"

	"code.cloudfoundry.org/bbs/db/migrations"
	"code.cloudfoundry.org/bbs/db/sqldb"
	"code.cloudfoundry.org/bbs/db/sqldb/helpers"
	"code.cloudfoundry.org/bbs/db/sqldb/helpers/monitor"
	"code.cloudfoundry.org/bbs/encryption/encryptionfakes"
	"code.cloudfoundry.org/bbs/guidprovider"
	"code.cloudfoundry.org/bbs/handlers"
	"code.cloudfoundry.org/bbs/migration"
	"code.cloudfoundry.org/bbs/models"
	"code.cloudfoundry.org/bbs/test_helpers"
	"code.cloudfoundry.org/clock/fakeclock"
	"code.cloudfoundry.org/diego-logging-client/testhelpers"
	"code.cloudfoundry.org/lager/lagertest"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

var _ = Describe("Context", func() {
	var (
		logger           *lagertest.TestLogger
		handler          *handlers.ActualLRPHandler
		sqlConn          *sql.DB
		sqlProcess       ifrit.Process
		migrationProcess ifrit.Process
	)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("test")

		dbName := fmt.Sprintf("diego_%d", GinkgoParallelNode())
		sqlRunner := test_helpers.NewSQLRunner(dbName)
		sqlProcess = ginkgomon.Invoke(sqlRunner)

		var err error
		sqlConn, err = sql.Open(sqlRunner.DriverName(), sqlRunner.ConnectionString())
		Expect(err).NotTo(HaveOccurred())

		dbMonitor := monitor.New()
		monitoredDB := helpers.NewMonitoredDB(sqlConn, dbMonitor)

		convergenceWorkers := 20
		updateWorkers := 1000
		fakeCryptor := &encryptionfakes.FakeCryptor{}
		fakeClock := fakeclock.NewFakeClock(time.Now())
		fakeMetronClient := &testhelpers.FakeIngressClient{}
		sqlDB := sqldb.NewSQLDB(
			monitoredDB,
			convergenceWorkers,
			updateWorkers,
			fakeCryptor,
			guidprovider.DefaultGuidProvider,
			fakeClock,
			sqlRunner.DriverName(),
			fakeMetronClient,
		)
		err = sqlDB.CreateConfigurationsTable(context.Background(), logger)
		Expect(err).NotTo(HaveOccurred())

		migrationsDone := make(chan struct{})

		migrationManager := migration.NewManager(
			logger,
			sqlDB,
			sqlConn,
			fakeCryptor,
			migrations.AllMigrations(),
			migrationsDone,
			fakeClock,
			sqlRunner.DriverName(),
			fakeMetronClient,
		)
		migrationProcess = ifrit.Invoke(migrationManager)
		Eventually(migrationsDone).Should(BeClosed())

		exitCh := make(chan struct{}, 1)
		handler = handlers.NewActualLRPHandler(sqlDB, exitCh)
	})

	AfterEach(func() {
		Expect(sqlConn.Close()).To(Succeed())
		ginkgomon.Kill(sqlProcess)
		ginkgomon.Kill(migrationProcess)
	})

	Context("when request is cancelled", func() {
		var sleepStarting chan struct{}

		BeforeEach(func() {
			sqlConn.SetMaxOpenConns(1)
			sleepStarting = make(chan struct{})
			go func() {
				defer GinkgoRecover()
				var sleepQuery string
				if test_helpers.UseMySQL() {
					sleepQuery = "select sleep(600);"
				} else if test_helpers.UsePostgres() {
					sleepQuery = `--pg_sleep_query_context_test
            select pg_sleep(600);`
				} else {
					Fail("unknown db driver")
				}
				close(sleepStarting)
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
			<-sleepStarting
			ctxWithCancel, cancelFn := context.WithCancel(context.Background())

			requestBody := &models.ActualLRPsRequest{}
			request := newTestRequest(requestBody).WithContext(ctxWithCancel)
			responseRecorder := httptest.NewRecorder()
			finishedRequest := make(chan struct{}, 1)

			go func() {
				defer GinkgoRecover()
				handler.ActualLRPs(logger, responseRecorder, request)

				response := models.ActualLRPsResponse{}
				err := response.Unmarshal(responseRecorder.Body.Bytes())
				Expect(err).NotTo(HaveOccurred())

				Expect(response.Error).To(HaveOccurred())
				Expect(response.Error.Error()).To(ContainSubstring(context.Canceled.Error()))
				close(finishedRequest)
			}()

			Eventually(logger).Should(gbytes.Say("actual-lrps.starting"))

			cancelFn()

			Eventually(finishedRequest, 5*time.Second).Should(BeClosed())
		})
	})
})
