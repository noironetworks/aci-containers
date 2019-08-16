package fakesqldriver_test

import (
	"database/sql/driver"
	"strings"

	"code.cloudfoundry.org/bbs/db/sqldb/fakesqldriver/fakesqldriverfakes"
	"code.cloudfoundry.org/bbs/models"
	"github.com/go-sql-driver/mysql"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Deadlocks", func() {
	BeforeEach(func() {
		fakeConn.PrepareStub = func(query string) (driver.Stmt, error) {
			fakeStmt := &fakesqldriverfakes.FakeStmt{}
			fakeStmt.NumInputReturns(strings.Count(query, "?"))
			fakeStmt.ExecReturns(nil, &mysql.MySQLError{Number: 1213})
			fakeStmt.QueryReturns(nil, &mysql.MySQLError{Number: 1213})
			return fakeStmt, nil
		}
	})

	Context("Domains", func() {
		It("retries on deadlocks", func() {
			_, err := sqlDB.FreshDomains(ctx, logger)
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("UpsertDomain", func() {
		It("retries on deadlocks", func() {
			err := sqlDB.UpsertDomain(ctx, logger, "", 0)
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("EncryptionKeyLabel", func() {
		It("retries on deadlocks", func() {
			_, err := sqlDB.EncryptionKeyLabel(ctx, logger)
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("SetEncryptionKeyLabel", func() {
		It("retries on deadlocks", func() {
			err := sqlDB.SetEncryptionKeyLabel(ctx, logger, "")
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("RemoveEvacuatingActualLRP", func() {
		It("retries on deadlocks", func() {
			err := sqlDB.RemoveEvacuatingActualLRP(ctx, logger, &models.ActualLRPKey{}, nil)
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("DesireTask", func() {
		It("retries on deadlocks", func() {
			_, err := sqlDB.DesireTask(ctx, logger, &models.TaskDefinition{}, "", "")
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("ActualLRPs", func() {
		It("retries on deadlocks", func() {
			_, err := sqlDB.ActualLRPs(ctx, logger, models.ActualLRPFilter{})
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("CancelTask", func() {
		It("retries on deadlocks", func() {
			_, _, _, err := sqlDB.CancelTask(ctx, logger, "")
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("ClaimActualLRP", func() {
		It("retries on deadlocks", func() {
			_, _, err := sqlDB.ClaimActualLRP(ctx, logger, "", 0, &models.ActualLRPInstanceKey{})
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("CompleteTask", func() {
		It("retries on deadlocks", func() {
			_, _, err := sqlDB.CompleteTask(ctx, logger, "", "", true, "", "")
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("CrashActualLRP", func() {
		It("retries on deadlocks", func() {
			_, _, _, err := sqlDB.CrashActualLRP(ctx, logger, &models.ActualLRPKey{}, &models.ActualLRPInstanceKey{}, "")
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("CreateUnclaimedActualLRP", func() {
		It("retries on deadlocks", func() {
			_, err := sqlDB.CreateUnclaimedActualLRP(ctx, logger, &models.ActualLRPKey{})
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("DeleteTask", func() {
		It("retries on deadlocks", func() {
			_, err := sqlDB.DeleteTask(ctx, logger, "")
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("DesireLRP", func() {
		It("retries on deadlocks", func() {
			err := sqlDB.DesireLRP(ctx, logger, &models.DesiredLRP{})
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("DesiredLRPByProcessGuid", func() {
		It("retries on deadlocks", func() {
			_, err := sqlDB.DesiredLRPByProcessGuid(ctx, logger, "")
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("DesiredLRPSchedulingInfos", func() {
		It("retries on deadlocks", func() {
			_, err := sqlDB.DesiredLRPSchedulingInfos(ctx, logger, models.DesiredLRPFilter{})
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("DesiredLRPs", func() {
		It("retries on deadlocks", func() {
			_, err := sqlDB.DesiredLRPs(ctx, logger, models.DesiredLRPFilter{})
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("EvacuateActualLRP", func() {
		It("retries on deadlocks", func() {
			_, err := sqlDB.EvacuateActualLRP(ctx, logger, &models.ActualLRPKey{}, &models.ActualLRPInstanceKey{}, &models.ActualLRPNetInfo{})
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("FailActualLRP", func() {
		It("retries on deadlocks", func() {
			_, _, err := sqlDB.FailActualLRP(ctx, logger, &models.ActualLRPKey{}, "")
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("FailTask", func() {
		It("retries on deadlocks", func() {
			_, _, err := sqlDB.FailTask(ctx, logger, "", "")
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("RemoveActualLRP", func() {
		It("retries on deadlocks", func() {
			err := sqlDB.RemoveActualLRP(ctx, logger, "", 0, &models.ActualLRPInstanceKey{})
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("RemoveDesiredLRP", func() {
		It("retries on deadlocks", func() {
			err := sqlDB.RemoveDesiredLRP(ctx, logger, "")
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("ResolvingTask", func() {
		It("retries on deadlocks", func() {
			_, _, err := sqlDB.ResolvingTask(ctx, logger, "")
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("SetVersion", func() {
		It("retries on deadlocks", func() {
			err := sqlDB.SetVersion(ctx, logger, &models.Version{})
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("StartActualLRP", func() {
		It("retries on deadlocks", func() {
			_, _, err := sqlDB.StartActualLRP(ctx, logger, &models.ActualLRPKey{}, &models.ActualLRPInstanceKey{}, &models.ActualLRPNetInfo{})
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("StartTask", func() {
		It("retries on deadlocks", func() {
			_, _, _, err := sqlDB.StartTask(ctx, logger, "", "")
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("TaskByGuid", func() {
		It("retries on deadlocks", func() {
			_, err := sqlDB.TaskByGuid(ctx, logger, "")
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("Tasks", func() {
		It("retries on deadlocks", func() {
			_, err := sqlDB.Tasks(ctx, logger, models.TaskFilter{})
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("UnclaimActualLRP", func() {
		It("retries on deadlocks", func() {
			_, _, err := sqlDB.UnclaimActualLRP(ctx, logger, &models.ActualLRPKey{})
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("UpdateDesiredLRP", func() {
		It("retries on deadlocks", func() {
			_, err := sqlDB.UpdateDesiredLRP(ctx, logger, "", &models.DesiredLRPUpdate{})
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})

	Context("Version", func() {
		It("retries on deadlocks", func() {
			_, err := sqlDB.Version(ctx, logger)
			Expect(err).To(HaveOccurred())
			Expect(fakeConn.BeginCallCount()).To(Equal(3))
		})
	})
})
