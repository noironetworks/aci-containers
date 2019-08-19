// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/enums/criterion_category_locale_availability_mode.proto

package enums

import (
	fmt "fmt"
	math "math"

	proto "github.com/golang/protobuf/proto"
	_ "google.golang.org/genproto/googleapis/api/annotations"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

// Enum containing the possible CriterionCategoryLocaleAvailabilityMode.
type CriterionCategoryLocaleAvailabilityModeEnum_CriterionCategoryLocaleAvailabilityMode int32

const (
	// Not specified.
	CriterionCategoryLocaleAvailabilityModeEnum_UNSPECIFIED CriterionCategoryLocaleAvailabilityModeEnum_CriterionCategoryLocaleAvailabilityMode = 0
	// Used for return value only. Represents value unknown in this version.
	CriterionCategoryLocaleAvailabilityModeEnum_UNKNOWN CriterionCategoryLocaleAvailabilityModeEnum_CriterionCategoryLocaleAvailabilityMode = 1
	// The category is available to campaigns of all locales.
	CriterionCategoryLocaleAvailabilityModeEnum_ALL_LOCALES CriterionCategoryLocaleAvailabilityModeEnum_CriterionCategoryLocaleAvailabilityMode = 2
	// The category is available to campaigns within a list of countries,
	// regardless of language.
	CriterionCategoryLocaleAvailabilityModeEnum_COUNTRY_AND_ALL_LANGUAGES CriterionCategoryLocaleAvailabilityModeEnum_CriterionCategoryLocaleAvailabilityMode = 3
	// The category is available to campaigns within a list of languages,
	// regardless of country.
	CriterionCategoryLocaleAvailabilityModeEnum_LANGUAGE_AND_ALL_COUNTRIES CriterionCategoryLocaleAvailabilityModeEnum_CriterionCategoryLocaleAvailabilityMode = 4
	// The category is available to campaigns within a list of country, language
	// pairs.
	CriterionCategoryLocaleAvailabilityModeEnum_COUNTRY_AND_LANGUAGE CriterionCategoryLocaleAvailabilityModeEnum_CriterionCategoryLocaleAvailabilityMode = 5
)

var CriterionCategoryLocaleAvailabilityModeEnum_CriterionCategoryLocaleAvailabilityMode_name = map[int32]string{
	0: "UNSPECIFIED",
	1: "UNKNOWN",
	2: "ALL_LOCALES",
	3: "COUNTRY_AND_ALL_LANGUAGES",
	4: "LANGUAGE_AND_ALL_COUNTRIES",
	5: "COUNTRY_AND_LANGUAGE",
}

var CriterionCategoryLocaleAvailabilityModeEnum_CriterionCategoryLocaleAvailabilityMode_value = map[string]int32{
	"UNSPECIFIED":                0,
	"UNKNOWN":                    1,
	"ALL_LOCALES":                2,
	"COUNTRY_AND_ALL_LANGUAGES":  3,
	"LANGUAGE_AND_ALL_COUNTRIES": 4,
	"COUNTRY_AND_LANGUAGE":       5,
}

func (x CriterionCategoryLocaleAvailabilityModeEnum_CriterionCategoryLocaleAvailabilityMode) String() string {
	return proto.EnumName(CriterionCategoryLocaleAvailabilityModeEnum_CriterionCategoryLocaleAvailabilityMode_name, int32(x))
}

func (CriterionCategoryLocaleAvailabilityModeEnum_CriterionCategoryLocaleAvailabilityMode) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_cab68ed8e76c6679, []int{0, 0}
}

// Describes locale availabilty mode for a criterion availability - whether
// it's available globally, or a particular country with all languages, or a
// particular language with all countries, or a country-language pair.
type CriterionCategoryLocaleAvailabilityModeEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CriterionCategoryLocaleAvailabilityModeEnum) Reset() {
	*m = CriterionCategoryLocaleAvailabilityModeEnum{}
}
func (m *CriterionCategoryLocaleAvailabilityModeEnum) String() string {
	return proto.CompactTextString(m)
}
func (*CriterionCategoryLocaleAvailabilityModeEnum) ProtoMessage() {}
func (*CriterionCategoryLocaleAvailabilityModeEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_cab68ed8e76c6679, []int{0}
}

func (m *CriterionCategoryLocaleAvailabilityModeEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CriterionCategoryLocaleAvailabilityModeEnum.Unmarshal(m, b)
}
func (m *CriterionCategoryLocaleAvailabilityModeEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CriterionCategoryLocaleAvailabilityModeEnum.Marshal(b, m, deterministic)
}
func (m *CriterionCategoryLocaleAvailabilityModeEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CriterionCategoryLocaleAvailabilityModeEnum.Merge(m, src)
}
func (m *CriterionCategoryLocaleAvailabilityModeEnum) XXX_Size() int {
	return xxx_messageInfo_CriterionCategoryLocaleAvailabilityModeEnum.Size(m)
}
func (m *CriterionCategoryLocaleAvailabilityModeEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_CriterionCategoryLocaleAvailabilityModeEnum.DiscardUnknown(m)
}

var xxx_messageInfo_CriterionCategoryLocaleAvailabilityModeEnum proto.InternalMessageInfo

func init() {
	proto.RegisterEnum("google.ads.googleads.v1.enums.CriterionCategoryLocaleAvailabilityModeEnum_CriterionCategoryLocaleAvailabilityMode", CriterionCategoryLocaleAvailabilityModeEnum_CriterionCategoryLocaleAvailabilityMode_name, CriterionCategoryLocaleAvailabilityModeEnum_CriterionCategoryLocaleAvailabilityMode_value)
	proto.RegisterType((*CriterionCategoryLocaleAvailabilityModeEnum)(nil), "google.ads.googleads.v1.enums.CriterionCategoryLocaleAvailabilityModeEnum")
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/enums/criterion_category_locale_availability_mode.proto", fileDescriptor_cab68ed8e76c6679)
}

var fileDescriptor_cab68ed8e76c6679 = []byte{
	// 381 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x51, 0x4f, 0x8b, 0x9b, 0x40,
	0x1c, 0xad, 0xa6, 0x7f, 0x60, 0x72, 0xa8, 0x48, 0x0f, 0x6d, 0x68, 0x0a, 0xc9, 0xa5, 0x87, 0x96,
	0x11, 0xe9, 0x6d, 0x7a, 0x9a, 0x18, 0x2b, 0xa1, 0x56, 0x43, 0xad, 0x29, 0x2d, 0x82, 0x4c, 0x74,
	0x90, 0x01, 0x9d, 0x09, 0x8e, 0x09, 0xe4, 0xb8, 0x5f, 0x65, 0x8f, 0x7b, 0xdb, 0xaf, 0xb1, 0xdf,
	0x62, 0xaf, 0xfb, 0x29, 0x16, 0xc7, 0x28, 0xb9, 0xec, 0x92, 0x8b, 0x3c, 0xe7, 0xbd, 0xdf, 0x7b,
	0x33, 0xef, 0x07, 0xc2, 0x42, 0x88, 0xa2, 0xa4, 0x16, 0xc9, 0xa5, 0xd5, 0xc1, 0x16, 0x1d, 0x6c,
	0x8b, 0xf2, 0x7d, 0x25, 0xad, 0xac, 0x66, 0x0d, 0xad, 0x99, 0xe0, 0x69, 0x46, 0x1a, 0x5a, 0x88,
	0xfa, 0x98, 0x96, 0x22, 0x23, 0x25, 0x4d, 0xc9, 0x81, 0xb0, 0x92, 0x6c, 0x59, 0xc9, 0x9a, 0x63,
	0x5a, 0x89, 0x9c, 0xc2, 0x5d, 0x2d, 0x1a, 0x61, 0x4e, 0x3b, 0x17, 0x48, 0x72, 0x09, 0x07, 0x43,
	0x78, 0xb0, 0xa1, 0x32, 0x9c, 0x7c, 0xec, 0xf3, 0x76, 0xcc, 0x22, 0x9c, 0x8b, 0x86, 0x34, 0x4c,
	0x70, 0xd9, 0x0d, 0xcf, 0xef, 0x35, 0xf0, 0xc5, 0xe9, 0x23, 0x9d, 0x53, 0xa2, 0xaf, 0x02, 0xf1,
	0x59, 0xde, 0x2f, 0x91, 0x53, 0x97, 0xef, 0xab, 0xf9, 0xad, 0x06, 0x3e, 0x5f, 0xa8, 0x37, 0xdf,
	0x82, 0x71, 0x1c, 0x44, 0x6b, 0xd7, 0x59, 0xfd, 0x58, 0xb9, 0x4b, 0xe3, 0x85, 0x39, 0x06, 0x6f,
	0xe2, 0xe0, 0x67, 0x10, 0xfe, 0x0d, 0x0c, 0xad, 0x65, 0xb1, 0xef, 0xa7, 0x7e, 0xe8, 0x60, 0xdf,
	0x8d, 0x0c, 0xdd, 0x9c, 0x82, 0x0f, 0x4e, 0x18, 0x07, 0x7f, 0x7e, 0xff, 0x4b, 0x71, 0xb0, 0x4c,
	0x15, 0x89, 0x03, 0x2f, 0xc6, 0x9e, 0x1b, 0x19, 0x23, 0xf3, 0x13, 0x98, 0xf4, 0xbf, 0x03, 0xdf,
	0xe9, 0x57, 0x6e, 0x64, 0xbc, 0x34, 0xdf, 0x83, 0x77, 0xe7, 0xe3, 0xbd, 0xd6, 0x78, 0xb5, 0xb8,
	0xd2, 0xc1, 0x2c, 0x13, 0x15, 0x7c, 0xb6, 0xa7, 0xc5, 0xd7, 0x0b, 0x9f, 0xb5, 0x6e, 0x7b, 0x5b,
	0x6b, 0xff, 0x17, 0x27, 0xbb, 0x42, 0x94, 0x84, 0x17, 0x50, 0xd4, 0x85, 0x55, 0x50, 0xae, 0x5a,
	0xed, 0xf7, 0xba, 0x63, 0xf2, 0x89, 0x35, 0x7f, 0x57, 0xdf, 0x6b, 0x7d, 0xe4, 0x61, 0x7c, 0xa3,
	0x4f, 0xbd, 0xce, 0x0a, 0xe7, 0x12, 0x76, 0xb0, 0x45, 0x1b, 0x1b, 0xb6, 0x95, 0xcb, 0xbb, 0x9e,
	0x4f, 0x70, 0x2e, 0x93, 0x81, 0x4f, 0x36, 0x76, 0xa2, 0xf8, 0x07, 0x7d, 0xd6, 0x1d, 0x22, 0x84,
	0x73, 0x89, 0xd0, 0xa0, 0x40, 0x68, 0x63, 0x23, 0xa4, 0x34, 0xdb, 0xd7, 0xea, 0x62, 0xdf, 0x1e,
	0x03, 0x00, 0x00, 0xff, 0xff, 0xb4, 0xb7, 0x95, 0xe6, 0x7e, 0x02, 0x00, 0x00,
}