package models_test

import (
	"code.cloudfoundry.org/bbs/models"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Sidecar", func() {
	var sidecar models.Sidecar

	BeforeEach(func() {
		sidecar = models.Sidecar{}
	})

	Describe("Validate", func() {
		var assertSidecarValidationFailsWithMessage = func(sidecar models.Sidecar, substring string) {
			validationErr := sidecar.Validate()
			ExpectWithOffset(1, validationErr).To(HaveOccurred())
			ExpectWithOffset(1, validationErr.Error()).To(ContainSubstring(substring))
		}

		It("returns nil with a valid sidecar", func() {
			sidecar.Action = &models.Action{
				RunAction: &models.RunAction{
					Path: "foo",
					User: "bar",
				},
			}
			Expect(sidecar.Validate()).To(Succeed())
		})

		It("requires an action", func() {
			sidecar.Action = nil
			assertSidecarValidationFailsWithMessage(sidecar, "action")
		})

		It("requires an action with an inner action", func() {
			sidecar.Action = &models.Action{}
			assertSidecarValidationFailsWithMessage(sidecar, "action")
		})

		It("requires a valid action", func() {
			sidecar.Action = &models.Action{
				UploadAction: &models.UploadAction{
					From: "web_location",
				},
			}
			assertSidecarValidationFailsWithMessage(sidecar, "to")
		})

		It("requires a valid MemoryMb", func() {
			sidecar.MemoryMb = -1
			assertSidecarValidationFailsWithMessage(sidecar, "memory_mb")
		})

		It("requires a valid DiskMb", func() {
			sidecar.DiskMb = -1
			assertSidecarValidationFailsWithMessage(sidecar, "disk_mb")
		})
	})
})
