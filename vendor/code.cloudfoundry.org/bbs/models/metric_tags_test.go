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

	Describe("ConvertMetricTags", func() {
		It("converts a valid maps", func() {
			tags, err := models.ConvertMetricTags(map[string]*models.MetricTagValue{
				"foo": &models.MetricTagValue{Static: "bar"},
				"biz": &models.MetricTagValue{Dynamic: models.MetricTagDynamicValueIndex},
				"baz": &models.MetricTagValue{Dynamic: models.MetricTagDynamicValueInstanceGuid},
			}, map[models.MetricTagValue_DynamicValue]interface{}{
				models.MetricTagDynamicValueIndex:        int32(4),
				models.MetricTagDynamicValueInstanceGuid: "my-guid",
			})
			Expect(err).To(Succeed())
			Expect(tags).To(Equal(map[string]string{
				"foo": "bar",
				"biz": "4",
				"baz": "my-guid",
			}))
		})

		It("errors with invalid Index value", func() {
			_, err := models.ConvertMetricTags(map[string]*models.MetricTagValue{
				"foo": &models.MetricTagValue{Static: "bar"},
				"biz": &models.MetricTagValue{Dynamic: models.MetricTagDynamicValueIndex},
				"baz": &models.MetricTagValue{Dynamic: models.MetricTagDynamicValueInstanceGuid},
			}, map[models.MetricTagValue_DynamicValue]interface{}{
				models.MetricTagDynamicValueIndex:        "$44",
				models.MetricTagDynamicValueInstanceGuid: "my-guid",
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("could not convert value $44 of type string to int32"))
		})

		It("errors with invalid InstanceGuid value", func() {
			_, err := models.ConvertMetricTags(map[string]*models.MetricTagValue{
				"foo": &models.MetricTagValue{Static: "bar"},
				"biz": &models.MetricTagValue{Dynamic: models.MetricTagDynamicValueIndex},
				"baz": &models.MetricTagValue{Dynamic: models.MetricTagDynamicValueInstanceGuid},
			}, map[models.MetricTagValue_DynamicValue]interface{}{
				models.MetricTagDynamicValueIndex:        int32(33),
				models.MetricTagDynamicValueInstanceGuid: 55,
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("could not convert value 55 of type int to string"))
		})

		It("errors with nil dynamic value map", func() {
			_, err := models.ConvertMetricTags(map[string]*models.MetricTagValue{
				"foo": &models.MetricTagValue{Static: "bar"},
				"biz": &models.MetricTagValue{Dynamic: models.MetricTagDynamicValueIndex},
				"baz": &models.MetricTagValue{Dynamic: models.MetricTagDynamicValueInstanceGuid},
			}, map[models.MetricTagValue_DynamicValue]interface{}{})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("could not convert value <nil> of type <nil>"))
		})
	})
})
