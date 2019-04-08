package models_test

import (
	"encoding/json"

	"code.cloudfoundry.org/bbs/models"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("MetricTagValue", func() {
	Describe("Validate", func() {
		It("is valid when there is only a static value specified", func() {
			value := &models.MetricTagValue{
				Static: "some-value",
			}
			Expect(value.Validate()).To(Succeed())
		})

		It("is valid when there is only a dynamic value specified", func() {
			value := &models.MetricTagValue{
				Dynamic: models.MetricTagDynamicValueIndex,
			}
			Expect(value.Validate()).To(Succeed())
		})

		It("is not valid when there is an invalid dynamic value specified", func() {
			value := &models.MetricTagValue{
				Dynamic: 100,
			}
			Expect(value.Validate()).To(MatchError(ContainSubstring("dynamic")))
		})

		It("is not valid when both static and dynamic values are specified", func() {
			value := &models.MetricTagValue{
				Static:  "some-value",
				Dynamic: models.MetricTagDynamicValueIndex,
			}
			err := value.Validate()
			Expect(err).To(MatchError(ContainSubstring("static")))
			Expect(err).To(MatchError(ContainSubstring("dynamic")))
		})

		It("is not valid when neither static or dynamic values are specified", func() {
			value := &models.MetricTagValue{}
			err := value.Validate()
			Expect(err).To(MatchError(ContainSubstring("static")))
			Expect(err).To(MatchError(ContainSubstring("dynamic")))
		})
	})

	Describe("Dynamic", func() {
		Describe("serialization", func() {
			DescribeTable("marshals and unmarshals between the value and the expected JSON output",
				func(v models.MetricTagValue_DynamicValue, expectedJSON string) {
					Expect(json.Marshal(v)).To(MatchJSON(expectedJSON))
					var testV models.MetricTagValue_DynamicValue
					Expect(json.Unmarshal([]byte(expectedJSON), &testV)).To(Succeed())
					Expect(testV).To(Equal(v))
				},
				Entry("invalid", models.DynamicValueInvalid, `"DynamicValueInvalid"`),
				Entry("index", models.MetricTagDynamicValueIndex, `"INDEX"`),
				Entry("instance_guid", models.MetricTagDynamicValueInstanceGuid, `"INSTANCE_GUID"`),
			)
		})
	})
})
