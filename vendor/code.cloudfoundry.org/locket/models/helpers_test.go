package models_test

import (
	"code.cloudfoundry.org/locket/models"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("helpers", func() {
	Describe("GetType", func() {
		It("matches the correct type to the type code", func() {
			Expect(models.GetType(&models.Resource{TypeCode: models.PRESENCE})).To(Equal("presence"))
			Expect(models.GetType(&models.Resource{TypeCode: models.LOCK})).To(Equal("lock"))
			Expect(models.GetType(&models.Resource{Type: "sandwich", TypeCode: models.UNKNOWN})).To(Equal("sandwich"))
		})
	})

	Describe("GetTypeCode", func() {
		It("matches the correct type code to the type", func() {
			Expect(models.GetTypeCode("presence")).To(Equal(models.PRESENCE))
			Expect(models.GetTypeCode("lock")).To(Equal(models.LOCK))
			Expect(models.GetTypeCode("sandwich")).To(Equal(models.UNKNOWN))
		})
	})

	Describe("GetResource", func() {
		It("on an UNKNOWN type code, attempts to match the type code to the type", func() {
			resource1 := &models.Resource{
				Owner:    "thelizardking",
				Value:    "candoanything",
				Key:      "sandwich",
				TypeCode: models.UNKNOWN,
				Type:     "lock",
			}

			resource2 := &models.Resource{
				Owner:    "thelizardking",
				Value:    "candoanything",
				Key:      "sandwich",
				TypeCode: models.UNKNOWN,
				Type:     "whut",
			}

			Expect(models.GetResource(resource1).TypeCode).To(Equal(models.LOCK))
			Expect(models.GetResource(resource1).Type).To(Equal("lock"))

			Expect(models.GetResource(resource2).TypeCode).To(Equal(models.UNKNOWN))
			Expect(models.GetResource(resource2).Type).To(Equal("whut"))
		})

		It("on a known type code, matches the type to the type code", func() {
			resource1 := &models.Resource{
				Owner:    "thelizardking",
				Value:    "candoanything",
				Key:      "sandwich",
				TypeCode: models.LOCK,
				Type:     "whut",
			}

			resource2 := &models.Resource{
				Owner:    "thelizardking",
				Value:    "candoanything",
				Key:      "sandwich",
				TypeCode: models.PRESENCE,
				Type:     "whut",
			}

			Expect(models.GetResource(resource1).TypeCode).To(Equal(models.LOCK))
			Expect(models.GetResource(resource1).Type).To(Equal("lock"))

			Expect(models.GetResource(resource2).TypeCode).To(Equal(models.PRESENCE))
			Expect(models.GetResource(resource2).Type).To(Equal("presence"))
		})
	})
})
