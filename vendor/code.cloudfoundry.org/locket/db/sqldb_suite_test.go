package db_test

import (
	"database/sql"
	"fmt"

	"code.cloudfoundry.org/bbs/db/sqldb/helpers"
	"code.cloudfoundry.org/bbs/db/sqldb/helpers/monitor"
	"code.cloudfoundry.org/bbs/guidprovider/fakes"
	"code.cloudfoundry.org/bbs/test_helpers"
	"code.cloudfoundry.org/lager/lagertest"
	sqldb "code.cloudfoundry.org/locket/db"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	_ "github.com/lib/pq"

	"testing"
)

var (
	rawDB                                *sql.DB
	sqlDB                                *sqldb.SQLDB
	logger                               *lagertest.TestLogger
	fakeGUIDProvider                     *fakes.FakeGUIDProvider
	dbDriverName, dbBaseConnectionString string
	dbFlavor                             string
	sqlHelper                            helpers.SQLHelper
)

func TestSql(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "SQL DB Suite")
}

var _ = BeforeSuite(func() {
	var err error
	logger = lagertest.NewTestLogger("sql-db")

	if test_helpers.UsePostgres() {
		dbDriverName = "postgres"
		dbBaseConnectionString = "postgres://diego:diego_pw@localhost/"
		dbFlavor = helpers.Postgres
	} else if test_helpers.UseMySQL() {
		dbDriverName = "mysql"
		dbBaseConnectionString = "diego:diego_password@/"
		dbFlavor = helpers.MySQL
	} else {
		panic("Unsupported driver")
	}

	// mysql must be set up on localhost as described in the CONTRIBUTING.md doc
	// in diego-release.
	rawDB, err = sql.Open(dbDriverName, dbBaseConnectionString)
	Expect(err).NotTo(HaveOccurred())
	Expect(rawDB.Ping()).NotTo(HaveOccurred())

	_, err = rawDB.Exec(fmt.Sprintf("DROP DATABASE diego_%d", GinkgoParallelNode()))
	_, err = rawDB.Exec(fmt.Sprintf("CREATE DATABASE diego_%d", GinkgoParallelNode()))
	Expect(err).NotTo(HaveOccurred())

	rawDB, err = sql.Open(dbDriverName, fmt.Sprintf("%sdiego_%d", dbBaseConnectionString, GinkgoParallelNode()))
	Expect(err).NotTo(HaveOccurred())
	Expect(rawDB.Ping()).NotTo(HaveOccurred())

	fakeGUIDProvider = &fakes.FakeGUIDProvider{}
	db := helpers.NewMonitoredDB(rawDB, monitor.New())
	sqlDB = sqldb.NewSQLDB(db, dbFlavor, fakeGUIDProvider)
	err = sqlDB.CreateLockTable(logger)
	Expect(err).NotTo(HaveOccurred())

	sqlHelper = helpers.NewSQLHelper(dbFlavor)

	// ensures sqlDB matches the db.DB interface
	var _ sqldb.LockDB = sqlDB
})

var _ = BeforeEach(func() {

	// ensure that all sqldb functions being tested only require one connection
	// to operate, otherwise a deadlock can be caused in bbs. For more
	// information see https://www.pivotaltracker.com/story/show/136754083
	rawDB.SetMaxOpenConns(1)
})

var _ = AfterEach(func() {
	truncateTables(rawDB)
})

var _ = AfterSuite(func() {
	Expect(rawDB.Close()).NotTo(HaveOccurred())
	rawDB, err := sql.Open(dbDriverName, dbBaseConnectionString)
	Expect(err).NotTo(HaveOccurred())
	Expect(rawDB.Ping()).NotTo(HaveOccurred())
	_, err = rawDB.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS diego_%d", GinkgoParallelNode()))
	Expect(err).NotTo(HaveOccurred())
	Expect(rawDB.Close()).NotTo(HaveOccurred())
})

func truncateTables(db *sql.DB) {
	for _, query := range truncateTablesSQL {
		result, err := db.Exec(query)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.RowsAffected()).To(BeEquivalentTo(0))
	}
}

var truncateTablesSQL = []string{
	"TRUNCATE TABLE locks",
}
