package models_test

import (
	"encoding/json"

	"code.cloudfoundry.org/bbs/models"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("ImageLayer", func() {
	Describe("Validate", func() {
		var layer *models.ImageLayer

		Context("when 'url', 'destination_path', 'media_type' are specified", func() {
			It("is valid", func() {
				layer = &models.ImageLayer{
					Url:             "web_location",
					DestinationPath: "local_location",
					MediaType:       models.MediaTypeTgz,
					LayerType:       models.LayerTypeShared,
				}

				err := layer.Validate()
				Expect(err).NotTo(HaveOccurred())
			})

			Context("when the action also has valid 'digest_value' and 'digest_algorithm'", func() {
				It("is valid", func() {
					layer = &models.ImageLayer{
						Url:             "web_location",
						DestinationPath: "local_location",
						DigestValue:     "some digest",
						DigestAlgorithm: models.DigestAlgorithmSha256,
						MediaType:       models.MediaTypeTgz,
						LayerType:       models.LayerTypeExclusive,
					}

					err := layer.Validate()
					Expect(err).NotTo(HaveOccurred())
				})
			})
		})

		for _, testCase := range []ValidatorErrorCase{
			{
				"url",
				&models.ImageLayer{
					DestinationPath: "local_location",
				},
			},
			{
				"destination_path",
				&models.ImageLayer{
					Url: "web_location",
				},
			},
			{
				"layer_type",
				&models.ImageLayer{},
			},
			{
				"layer_type",
				&models.ImageLayer{
					LayerType: models.ImageLayer_Type(10),
				},
			},
			{
				"digest_value",
				&models.ImageLayer{
					Url:             "web_location",
					DestinationPath: "local_location",
					DigestAlgorithm: models.DigestAlgorithmSha256,
					MediaType:       models.MediaTypeTgz,
				},
			},
			{
				"digest_algorithm",
				&models.ImageLayer{
					Url:             "web_location",
					DestinationPath: "local_location",
					DigestValue:     "some digest",
					MediaType:       models.MediaTypeTgz,
				},
			},
			{
				"digest_value",
				&models.ImageLayer{
					Url:             "web_location",
					DestinationPath: "local_location",
					MediaType:       models.MediaTypeTgz,
					LayerType:       models.LayerTypeExclusive,
				},
			},
			{
				"digest_algorithm",
				&models.ImageLayer{
					Url:             "web_location",
					DestinationPath: "local_location",
					MediaType:       models.MediaTypeTgz,
					LayerType:       models.LayerTypeExclusive,
				},
			},
			{
				"digest_algorithm",
				&models.ImageLayer{
					Url:             "web_location",
					DestinationPath: "local_location",
					DigestAlgorithm: models.ImageLayer_DigestAlgorithm(5),
					DigestValue:     "some digest",
					MediaType:       models.MediaTypeTgz,
				},
			},
			{
				"media_type",
				&models.ImageLayer{
					Url:             "web_location",
					DestinationPath: "local_location",
					DigestAlgorithm: models.DigestAlgorithmSha256,
					DigestValue:     "some digest",
				},
			},
			{
				"media_type",
				&models.ImageLayer{
					Url:             "web_location",
					DestinationPath: "local_location",
					DigestAlgorithm: models.DigestAlgorithmSha256,
					DigestValue:     "some digest",
					MediaType:       models.ImageLayer_MediaType(9),
				},
			},
		} {
			testValidatorErrorCase(testCase)
		}
	})

	Describe("DigestAlgorithm", func() {
		Describe("serialization", func() {
			DescribeTable("marshals and unmarshals between the value and the expected JSON output",
				func(v models.ImageLayer_DigestAlgorithm, expectedJSON string) {
					Expect(json.Marshal(v)).To(MatchJSON(expectedJSON))
					var testV models.ImageLayer_DigestAlgorithm
					Expect(json.Unmarshal([]byte(expectedJSON), &testV)).To(Succeed())
					Expect(testV).To(Equal(v))
				},
				Entry("invalid", models.DigestAlgorithmInvalid, `"DigestAlgorithmInvalid"`),
				Entry("sha256", models.DigestAlgorithmSha256, `"SHA256"`),
				Entry("sha512", models.DigestAlgorithmSha512, `"SHA512"`),
			)
		})
	})

	Describe("MediaType", func() {
		Describe("serialization", func() {
			DescribeTable("marshals and unmarshals between the value and the expected JSON output",
				func(v models.ImageLayer_MediaType, expectedJSON string) {
					Expect(json.Marshal(v)).To(MatchJSON(expectedJSON))
					var testV models.ImageLayer_MediaType
					Expect(json.Unmarshal([]byte(expectedJSON), &testV)).To(Succeed())
					Expect(testV).To(Equal(v))
				},
				Entry("invalid", models.MediaTypeInvalid, `"MediaTypeInvalid"`),
				Entry("tgz", models.MediaTypeTgz, `"TGZ"`),
				Entry("tar", models.MediaTypeTar, `"TAR"`),
				Entry("zip", models.MediaTypeZip, `"ZIP"`),
			)
		})
	})

	Describe("Type", func() {
		Describe("serialization", func() {
			DescribeTable("marshals and unmarshals between the value and the expected JSON output",
				func(v models.ImageLayer_Type, expectedJSON string) {
					Expect(json.Marshal(v)).To(MatchJSON(expectedJSON))
					var testV models.ImageLayer_Type
					Expect(json.Unmarshal([]byte(expectedJSON), &testV)).To(Succeed())
					Expect(testV).To(Equal(v))
				},
				Entry("invalid", models.LayerTypeInvalid, `"LayerTypeInvalid"`),
				Entry("shared", models.LayerTypeShared, `"SHARED"`),
				Entry("exclusive", models.LayerTypeExclusive, `"EXCLUSIVE"`),
			)
		})
	})
})
