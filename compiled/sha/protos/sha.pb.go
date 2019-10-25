// Code generated by protoc-gen-go. DO NOT EDIT.
// source: sha/protos/sha.proto

package sha

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
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

type StorageScanner struct {
	NotificationConfigName string                  `protobuf:"bytes,1,opt,name=notificationConfigName,proto3" json:"notificationConfigName,omitempty"`
	Finding                *StorageScanner_Finding `protobuf:"bytes,2,opt,name=finding,proto3" json:"finding,omitempty"`
	XXX_NoUnkeyedLiteral   struct{}                `json:"-"`
	XXX_unrecognized       []byte                  `json:"-"`
	XXX_sizecache          int32                   `json:"-"`
}

func (m *StorageScanner) Reset()         { *m = StorageScanner{} }
func (m *StorageScanner) String() string { return proto.CompactTextString(m) }
func (*StorageScanner) ProtoMessage()    {}
func (*StorageScanner) Descriptor() ([]byte, []int) {
	return fileDescriptor_42ce1b275ac7c5c9, []int{0}
}

func (m *StorageScanner) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_StorageScanner.Unmarshal(m, b)
}
func (m *StorageScanner) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_StorageScanner.Marshal(b, m, deterministic)
}
func (m *StorageScanner) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StorageScanner.Merge(m, src)
}
func (m *StorageScanner) XXX_Size() int {
	return xxx_messageInfo_StorageScanner.Size(m)
}
func (m *StorageScanner) XXX_DiscardUnknown() {
	xxx_messageInfo_StorageScanner.DiscardUnknown(m)
}

var xxx_messageInfo_StorageScanner proto.InternalMessageInfo

func (m *StorageScanner) GetNotificationConfigName() string {
	if m != nil {
		return m.NotificationConfigName
	}
	return ""
}

func (m *StorageScanner) GetFinding() *StorageScanner_Finding {
	if m != nil {
		return m.Finding
	}
	return nil
}

type StorageScanner_SourceProperties struct {
	ProjectId            string   `protobuf:"bytes,1,opt,name=projectId,proto3" json:"projectId,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *StorageScanner_SourceProperties) Reset()         { *m = StorageScanner_SourceProperties{} }
func (m *StorageScanner_SourceProperties) String() string { return proto.CompactTextString(m) }
func (*StorageScanner_SourceProperties) ProtoMessage()    {}
func (*StorageScanner_SourceProperties) Descriptor() ([]byte, []int) {
	return fileDescriptor_42ce1b275ac7c5c9, []int{0, 0}
}

func (m *StorageScanner_SourceProperties) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_StorageScanner_SourceProperties.Unmarshal(m, b)
}
func (m *StorageScanner_SourceProperties) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_StorageScanner_SourceProperties.Marshal(b, m, deterministic)
}
func (m *StorageScanner_SourceProperties) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StorageScanner_SourceProperties.Merge(m, src)
}
func (m *StorageScanner_SourceProperties) XXX_Size() int {
	return xxx_messageInfo_StorageScanner_SourceProperties.Size(m)
}
func (m *StorageScanner_SourceProperties) XXX_DiscardUnknown() {
	xxx_messageInfo_StorageScanner_SourceProperties.DiscardUnknown(m)
}

var xxx_messageInfo_StorageScanner_SourceProperties proto.InternalMessageInfo

func (m *StorageScanner_SourceProperties) GetProjectId() string {
	if m != nil {
		return m.ProjectId
	}
	return ""
}

type StorageScanner_Finding struct {
	SourceProperties     *StorageScanner_SourceProperties `protobuf:"bytes,1,opt,name=sourceProperties,proto3" json:"sourceProperties,omitempty"`
	ResourceName         string                           `protobuf:"bytes,2,opt,name=resourceName,proto3" json:"resourceName,omitempty"`
	Category             string                           `protobuf:"bytes,3,opt,name=category,proto3" json:"category,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                         `json:"-"`
	XXX_unrecognized     []byte                           `json:"-"`
	XXX_sizecache        int32                            `json:"-"`
}

func (m *StorageScanner_Finding) Reset()         { *m = StorageScanner_Finding{} }
func (m *StorageScanner_Finding) String() string { return proto.CompactTextString(m) }
func (*StorageScanner_Finding) ProtoMessage()    {}
func (*StorageScanner_Finding) Descriptor() ([]byte, []int) {
	return fileDescriptor_42ce1b275ac7c5c9, []int{0, 1}
}

func (m *StorageScanner_Finding) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_StorageScanner_Finding.Unmarshal(m, b)
}
func (m *StorageScanner_Finding) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_StorageScanner_Finding.Marshal(b, m, deterministic)
}
func (m *StorageScanner_Finding) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StorageScanner_Finding.Merge(m, src)
}
func (m *StorageScanner_Finding) XXX_Size() int {
	return xxx_messageInfo_StorageScanner_Finding.Size(m)
}
func (m *StorageScanner_Finding) XXX_DiscardUnknown() {
	xxx_messageInfo_StorageScanner_Finding.DiscardUnknown(m)
}

var xxx_messageInfo_StorageScanner_Finding proto.InternalMessageInfo

func (m *StorageScanner_Finding) GetSourceProperties() *StorageScanner_SourceProperties {
	if m != nil {
		return m.SourceProperties
	}
	return nil
}

func (m *StorageScanner_Finding) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

func (m *StorageScanner_Finding) GetCategory() string {
	if m != nil {
		return m.Category
	}
	return ""
}

type FirewallScanner struct {
	NotificationConfigName string                   `protobuf:"bytes,1,opt,name=notificationConfigName,proto3" json:"notificationConfigName,omitempty"`
	Finding                *FirewallScanner_Finding `protobuf:"bytes,2,opt,name=finding,proto3" json:"finding,omitempty"`
	XXX_NoUnkeyedLiteral   struct{}                 `json:"-"`
	XXX_unrecognized       []byte                   `json:"-"`
	XXX_sizecache          int32                    `json:"-"`
}

func (m *FirewallScanner) Reset()         { *m = FirewallScanner{} }
func (m *FirewallScanner) String() string { return proto.CompactTextString(m) }
func (*FirewallScanner) ProtoMessage()    {}
func (*FirewallScanner) Descriptor() ([]byte, []int) {
	return fileDescriptor_42ce1b275ac7c5c9, []int{1}
}

func (m *FirewallScanner) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FirewallScanner.Unmarshal(m, b)
}
func (m *FirewallScanner) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FirewallScanner.Marshal(b, m, deterministic)
}
func (m *FirewallScanner) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FirewallScanner.Merge(m, src)
}
func (m *FirewallScanner) XXX_Size() int {
	return xxx_messageInfo_FirewallScanner.Size(m)
}
func (m *FirewallScanner) XXX_DiscardUnknown() {
	xxx_messageInfo_FirewallScanner.DiscardUnknown(m)
}

var xxx_messageInfo_FirewallScanner proto.InternalMessageInfo

func (m *FirewallScanner) GetNotificationConfigName() string {
	if m != nil {
		return m.NotificationConfigName
	}
	return ""
}

func (m *FirewallScanner) GetFinding() *FirewallScanner_Finding {
	if m != nil {
		return m.Finding
	}
	return nil
}

type FirewallScanner_SourceProperties struct {
	ProjectId            string   `protobuf:"bytes,1,opt,name=projectId,proto3" json:"projectId,omitempty"`
	Allowed              string   `protobuf:"bytes,2,opt,name=allowed,proto3" json:"allowed,omitempty"`
	AllowedIpRange       string   `protobuf:"bytes,3,opt,name=allowedIpRange,proto3" json:"allowedIpRange,omitempty"`
	ActivationTrigger    string   `protobuf:"bytes,4,opt,name=activationTrigger,proto3" json:"activationTrigger,omitempty"`
	SourceRange          string   `protobuf:"bytes,5,opt,name=sourceRange,proto3" json:"sourceRange,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *FirewallScanner_SourceProperties) Reset()         { *m = FirewallScanner_SourceProperties{} }
func (m *FirewallScanner_SourceProperties) String() string { return proto.CompactTextString(m) }
func (*FirewallScanner_SourceProperties) ProtoMessage()    {}
func (*FirewallScanner_SourceProperties) Descriptor() ([]byte, []int) {
	return fileDescriptor_42ce1b275ac7c5c9, []int{1, 0}
}

func (m *FirewallScanner_SourceProperties) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FirewallScanner_SourceProperties.Unmarshal(m, b)
}
func (m *FirewallScanner_SourceProperties) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FirewallScanner_SourceProperties.Marshal(b, m, deterministic)
}
func (m *FirewallScanner_SourceProperties) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FirewallScanner_SourceProperties.Merge(m, src)
}
func (m *FirewallScanner_SourceProperties) XXX_Size() int {
	return xxx_messageInfo_FirewallScanner_SourceProperties.Size(m)
}
func (m *FirewallScanner_SourceProperties) XXX_DiscardUnknown() {
	xxx_messageInfo_FirewallScanner_SourceProperties.DiscardUnknown(m)
}

var xxx_messageInfo_FirewallScanner_SourceProperties proto.InternalMessageInfo

func (m *FirewallScanner_SourceProperties) GetProjectId() string {
	if m != nil {
		return m.ProjectId
	}
	return ""
}

func (m *FirewallScanner_SourceProperties) GetAllowed() string {
	if m != nil {
		return m.Allowed
	}
	return ""
}

func (m *FirewallScanner_SourceProperties) GetAllowedIpRange() string {
	if m != nil {
		return m.AllowedIpRange
	}
	return ""
}

func (m *FirewallScanner_SourceProperties) GetActivationTrigger() string {
	if m != nil {
		return m.ActivationTrigger
	}
	return ""
}

func (m *FirewallScanner_SourceProperties) GetSourceRange() string {
	if m != nil {
		return m.SourceRange
	}
	return ""
}

type FirewallScanner_Finding struct {
	SourceProperties     *FirewallScanner_SourceProperties `protobuf:"bytes,1,opt,name=sourceProperties,proto3" json:"sourceProperties,omitempty"`
	Category             string                            `protobuf:"bytes,2,opt,name=category,proto3" json:"category,omitempty"`
	ResourceName         string                            `protobuf:"bytes,3,opt,name=resourceName,proto3" json:"resourceName,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                          `json:"-"`
	XXX_unrecognized     []byte                            `json:"-"`
	XXX_sizecache        int32                             `json:"-"`
}

func (m *FirewallScanner_Finding) Reset()         { *m = FirewallScanner_Finding{} }
func (m *FirewallScanner_Finding) String() string { return proto.CompactTextString(m) }
func (*FirewallScanner_Finding) ProtoMessage()    {}
func (*FirewallScanner_Finding) Descriptor() ([]byte, []int) {
	return fileDescriptor_42ce1b275ac7c5c9, []int{1, 1}
}

func (m *FirewallScanner_Finding) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FirewallScanner_Finding.Unmarshal(m, b)
}
func (m *FirewallScanner_Finding) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FirewallScanner_Finding.Marshal(b, m, deterministic)
}
func (m *FirewallScanner_Finding) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FirewallScanner_Finding.Merge(m, src)
}
func (m *FirewallScanner_Finding) XXX_Size() int {
	return xxx_messageInfo_FirewallScanner_Finding.Size(m)
}
func (m *FirewallScanner_Finding) XXX_DiscardUnknown() {
	xxx_messageInfo_FirewallScanner_Finding.DiscardUnknown(m)
}

var xxx_messageInfo_FirewallScanner_Finding proto.InternalMessageInfo

func (m *FirewallScanner_Finding) GetSourceProperties() *FirewallScanner_SourceProperties {
	if m != nil {
		return m.SourceProperties
	}
	return nil
}

func (m *FirewallScanner_Finding) GetCategory() string {
	if m != nil {
		return m.Category
	}
	return ""
}

func (m *FirewallScanner_Finding) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

type ComputeInstanceScanner struct {
	NotificationConfigName string                          `protobuf:"bytes,1,opt,name=notificationConfigName,proto3" json:"notificationConfigName,omitempty"`
	Finding                *ComputeInstanceScanner_Finding `protobuf:"bytes,2,opt,name=finding,proto3" json:"finding,omitempty"`
	XXX_NoUnkeyedLiteral   struct{}                        `json:"-"`
	XXX_unrecognized       []byte                          `json:"-"`
	XXX_sizecache          int32                           `json:"-"`
}

func (m *ComputeInstanceScanner) Reset()         { *m = ComputeInstanceScanner{} }
func (m *ComputeInstanceScanner) String() string { return proto.CompactTextString(m) }
func (*ComputeInstanceScanner) ProtoMessage()    {}
func (*ComputeInstanceScanner) Descriptor() ([]byte, []int) {
	return fileDescriptor_42ce1b275ac7c5c9, []int{2}
}

func (m *ComputeInstanceScanner) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ComputeInstanceScanner.Unmarshal(m, b)
}
func (m *ComputeInstanceScanner) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ComputeInstanceScanner.Marshal(b, m, deterministic)
}
func (m *ComputeInstanceScanner) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ComputeInstanceScanner.Merge(m, src)
}
func (m *ComputeInstanceScanner) XXX_Size() int {
	return xxx_messageInfo_ComputeInstanceScanner.Size(m)
}
func (m *ComputeInstanceScanner) XXX_DiscardUnknown() {
	xxx_messageInfo_ComputeInstanceScanner.DiscardUnknown(m)
}

var xxx_messageInfo_ComputeInstanceScanner proto.InternalMessageInfo

func (m *ComputeInstanceScanner) GetNotificationConfigName() string {
	if m != nil {
		return m.NotificationConfigName
	}
	return ""
}

func (m *ComputeInstanceScanner) GetFinding() *ComputeInstanceScanner_Finding {
	if m != nil {
		return m.Finding
	}
	return nil
}

type ComputeInstanceScanner_SourceProperties struct {
	ProjectID            string   `protobuf:"bytes,1,opt,name=projectID,proto3" json:"projectID,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ComputeInstanceScanner_SourceProperties) Reset() {
	*m = ComputeInstanceScanner_SourceProperties{}
}
func (m *ComputeInstanceScanner_SourceProperties) String() string { return proto.CompactTextString(m) }
func (*ComputeInstanceScanner_SourceProperties) ProtoMessage()    {}
func (*ComputeInstanceScanner_SourceProperties) Descriptor() ([]byte, []int) {
	return fileDescriptor_42ce1b275ac7c5c9, []int{2, 0}
}

func (m *ComputeInstanceScanner_SourceProperties) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ComputeInstanceScanner_SourceProperties.Unmarshal(m, b)
}
func (m *ComputeInstanceScanner_SourceProperties) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ComputeInstanceScanner_SourceProperties.Marshal(b, m, deterministic)
}
func (m *ComputeInstanceScanner_SourceProperties) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ComputeInstanceScanner_SourceProperties.Merge(m, src)
}
func (m *ComputeInstanceScanner_SourceProperties) XXX_Size() int {
	return xxx_messageInfo_ComputeInstanceScanner_SourceProperties.Size(m)
}
func (m *ComputeInstanceScanner_SourceProperties) XXX_DiscardUnknown() {
	xxx_messageInfo_ComputeInstanceScanner_SourceProperties.DiscardUnknown(m)
}

var xxx_messageInfo_ComputeInstanceScanner_SourceProperties proto.InternalMessageInfo

func (m *ComputeInstanceScanner_SourceProperties) GetProjectID() string {
	if m != nil {
		return m.ProjectID
	}
	return ""
}

type ComputeInstanceScanner_Finding struct {
	SourceProperties     *ComputeInstanceScanner_SourceProperties `protobuf:"bytes,1,opt,name=sourceProperties,proto3" json:"sourceProperties,omitempty"`
	Category             string                                   `protobuf:"bytes,2,opt,name=category,proto3" json:"category,omitempty"`
	ResourceName         string                                   `protobuf:"bytes,3,opt,name=resourceName,proto3" json:"resourceName,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                                 `json:"-"`
	XXX_unrecognized     []byte                                   `json:"-"`
	XXX_sizecache        int32                                    `json:"-"`
}

func (m *ComputeInstanceScanner_Finding) Reset()         { *m = ComputeInstanceScanner_Finding{} }
func (m *ComputeInstanceScanner_Finding) String() string { return proto.CompactTextString(m) }
func (*ComputeInstanceScanner_Finding) ProtoMessage()    {}
func (*ComputeInstanceScanner_Finding) Descriptor() ([]byte, []int) {
	return fileDescriptor_42ce1b275ac7c5c9, []int{2, 1}
}

func (m *ComputeInstanceScanner_Finding) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ComputeInstanceScanner_Finding.Unmarshal(m, b)
}
func (m *ComputeInstanceScanner_Finding) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ComputeInstanceScanner_Finding.Marshal(b, m, deterministic)
}
func (m *ComputeInstanceScanner_Finding) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ComputeInstanceScanner_Finding.Merge(m, src)
}
func (m *ComputeInstanceScanner_Finding) XXX_Size() int {
	return xxx_messageInfo_ComputeInstanceScanner_Finding.Size(m)
}
func (m *ComputeInstanceScanner_Finding) XXX_DiscardUnknown() {
	xxx_messageInfo_ComputeInstanceScanner_Finding.DiscardUnknown(m)
}

var xxx_messageInfo_ComputeInstanceScanner_Finding proto.InternalMessageInfo

func (m *ComputeInstanceScanner_Finding) GetSourceProperties() *ComputeInstanceScanner_SourceProperties {
	if m != nil {
		return m.SourceProperties
	}
	return nil
}

func (m *ComputeInstanceScanner_Finding) GetCategory() string {
	if m != nil {
		return m.Category
	}
	return ""
}

func (m *ComputeInstanceScanner_Finding) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

type IamScanner struct {
	NotificationConfigName string              `protobuf:"bytes,1,opt,name=notificationConfigName,proto3" json:"notificationConfigName,omitempty"`
	Finding                *IamScanner_Finding `protobuf:"bytes,2,opt,name=finding,proto3" json:"finding,omitempty"`
	XXX_NoUnkeyedLiteral   struct{}            `json:"-"`
	XXX_unrecognized       []byte              `json:"-"`
	XXX_sizecache          int32               `json:"-"`
}

func (m *IamScanner) Reset()         { *m = IamScanner{} }
func (m *IamScanner) String() string { return proto.CompactTextString(m) }
func (*IamScanner) ProtoMessage()    {}
func (*IamScanner) Descriptor() ([]byte, []int) {
	return fileDescriptor_42ce1b275ac7c5c9, []int{3}
}

func (m *IamScanner) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_IamScanner.Unmarshal(m, b)
}
func (m *IamScanner) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_IamScanner.Marshal(b, m, deterministic)
}
func (m *IamScanner) XXX_Merge(src proto.Message) {
	xxx_messageInfo_IamScanner.Merge(m, src)
}
func (m *IamScanner) XXX_Size() int {
	return xxx_messageInfo_IamScanner.Size(m)
}
func (m *IamScanner) XXX_DiscardUnknown() {
	xxx_messageInfo_IamScanner.DiscardUnknown(m)
}

var xxx_messageInfo_IamScanner proto.InternalMessageInfo

func (m *IamScanner) GetNotificationConfigName() string {
	if m != nil {
		return m.NotificationConfigName
	}
	return ""
}

func (m *IamScanner) GetFinding() *IamScanner_Finding {
	if m != nil {
		return m.Finding
	}
	return nil
}

type IamScanner_SourceProperties struct {
	ProjectID            string   `protobuf:"bytes,1,opt,name=projectID,proto3" json:"projectID,omitempty"`
	OffendingIamRoles    string   `protobuf:"bytes,2,opt,name=offendingIamRoles,proto3" json:"offendingIamRoles,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *IamScanner_SourceProperties) Reset()         { *m = IamScanner_SourceProperties{} }
func (m *IamScanner_SourceProperties) String() string { return proto.CompactTextString(m) }
func (*IamScanner_SourceProperties) ProtoMessage()    {}
func (*IamScanner_SourceProperties) Descriptor() ([]byte, []int) {
	return fileDescriptor_42ce1b275ac7c5c9, []int{3, 0}
}

func (m *IamScanner_SourceProperties) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_IamScanner_SourceProperties.Unmarshal(m, b)
}
func (m *IamScanner_SourceProperties) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_IamScanner_SourceProperties.Marshal(b, m, deterministic)
}
func (m *IamScanner_SourceProperties) XXX_Merge(src proto.Message) {
	xxx_messageInfo_IamScanner_SourceProperties.Merge(m, src)
}
func (m *IamScanner_SourceProperties) XXX_Size() int {
	return xxx_messageInfo_IamScanner_SourceProperties.Size(m)
}
func (m *IamScanner_SourceProperties) XXX_DiscardUnknown() {
	xxx_messageInfo_IamScanner_SourceProperties.DiscardUnknown(m)
}

var xxx_messageInfo_IamScanner_SourceProperties proto.InternalMessageInfo

func (m *IamScanner_SourceProperties) GetProjectID() string {
	if m != nil {
		return m.ProjectID
	}
	return ""
}

func (m *IamScanner_SourceProperties) GetOffendingIamRoles() string {
	if m != nil {
		return m.OffendingIamRoles
	}
	return ""
}

type IamScanner_Finding struct {
	SourceProperties     *IamScanner_SourceProperties `protobuf:"bytes,1,opt,name=sourceProperties,proto3" json:"sourceProperties,omitempty"`
	Category             string                       `protobuf:"bytes,2,opt,name=category,proto3" json:"category,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                     `json:"-"`
	XXX_unrecognized     []byte                       `json:"-"`
	XXX_sizecache        int32                        `json:"-"`
}

func (m *IamScanner_Finding) Reset()         { *m = IamScanner_Finding{} }
func (m *IamScanner_Finding) String() string { return proto.CompactTextString(m) }
func (*IamScanner_Finding) ProtoMessage()    {}
func (*IamScanner_Finding) Descriptor() ([]byte, []int) {
	return fileDescriptor_42ce1b275ac7c5c9, []int{3, 1}
}

func (m *IamScanner_Finding) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_IamScanner_Finding.Unmarshal(m, b)
}
func (m *IamScanner_Finding) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_IamScanner_Finding.Marshal(b, m, deterministic)
}
func (m *IamScanner_Finding) XXX_Merge(src proto.Message) {
	xxx_messageInfo_IamScanner_Finding.Merge(m, src)
}
func (m *IamScanner_Finding) XXX_Size() int {
	return xxx_messageInfo_IamScanner_Finding.Size(m)
}
func (m *IamScanner_Finding) XXX_DiscardUnknown() {
	xxx_messageInfo_IamScanner_Finding.DiscardUnknown(m)
}

var xxx_messageInfo_IamScanner_Finding proto.InternalMessageInfo

func (m *IamScanner_Finding) GetSourceProperties() *IamScanner_SourceProperties {
	if m != nil {
		return m.SourceProperties
	}
	return nil
}

func (m *IamScanner_Finding) GetCategory() string {
	if m != nil {
		return m.Category
	}
	return ""
}

type SqlScanner struct {
	NotificationConfigName string              `protobuf:"bytes,1,opt,name=notificationConfigName,proto3" json:"notificationConfigName,omitempty"`
	Finding                *SqlScanner_Finding `protobuf:"bytes,2,opt,name=finding,proto3" json:"finding,omitempty"`
	XXX_NoUnkeyedLiteral   struct{}            `json:"-"`
	XXX_unrecognized       []byte              `json:"-"`
	XXX_sizecache          int32               `json:"-"`
}

func (m *SqlScanner) Reset()         { *m = SqlScanner{} }
func (m *SqlScanner) String() string { return proto.CompactTextString(m) }
func (*SqlScanner) ProtoMessage()    {}
func (*SqlScanner) Descriptor() ([]byte, []int) {
	return fileDescriptor_42ce1b275ac7c5c9, []int{4}
}

func (m *SqlScanner) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SqlScanner.Unmarshal(m, b)
}
func (m *SqlScanner) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SqlScanner.Marshal(b, m, deterministic)
}
func (m *SqlScanner) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SqlScanner.Merge(m, src)
}
func (m *SqlScanner) XXX_Size() int {
	return xxx_messageInfo_SqlScanner.Size(m)
}
func (m *SqlScanner) XXX_DiscardUnknown() {
	xxx_messageInfo_SqlScanner.DiscardUnknown(m)
}

var xxx_messageInfo_SqlScanner proto.InternalMessageInfo

func (m *SqlScanner) GetNotificationConfigName() string {
	if m != nil {
		return m.NotificationConfigName
	}
	return ""
}

func (m *SqlScanner) GetFinding() *SqlScanner_Finding {
	if m != nil {
		return m.Finding
	}
	return nil
}

type SqlScanner_SourceProperties struct {
	ProjectID            string   `protobuf:"bytes,1,opt,name=projectID,proto3" json:"projectID,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SqlScanner_SourceProperties) Reset()         { *m = SqlScanner_SourceProperties{} }
func (m *SqlScanner_SourceProperties) String() string { return proto.CompactTextString(m) }
func (*SqlScanner_SourceProperties) ProtoMessage()    {}
func (*SqlScanner_SourceProperties) Descriptor() ([]byte, []int) {
	return fileDescriptor_42ce1b275ac7c5c9, []int{4, 0}
}

func (m *SqlScanner_SourceProperties) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SqlScanner_SourceProperties.Unmarshal(m, b)
}
func (m *SqlScanner_SourceProperties) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SqlScanner_SourceProperties.Marshal(b, m, deterministic)
}
func (m *SqlScanner_SourceProperties) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SqlScanner_SourceProperties.Merge(m, src)
}
func (m *SqlScanner_SourceProperties) XXX_Size() int {
	return xxx_messageInfo_SqlScanner_SourceProperties.Size(m)
}
func (m *SqlScanner_SourceProperties) XXX_DiscardUnknown() {
	xxx_messageInfo_SqlScanner_SourceProperties.DiscardUnknown(m)
}

var xxx_messageInfo_SqlScanner_SourceProperties proto.InternalMessageInfo

func (m *SqlScanner_SourceProperties) GetProjectID() string {
	if m != nil {
		return m.ProjectID
	}
	return ""
}

type SqlScanner_Finding struct {
	SourceProperties     *SqlScanner_SourceProperties `protobuf:"bytes,1,opt,name=sourceProperties,proto3" json:"sourceProperties,omitempty"`
	Category             string                       `protobuf:"bytes,2,opt,name=category,proto3" json:"category,omitempty"`
	ResourceName         string                       `protobuf:"bytes,3,opt,name=resourceName,proto3" json:"resourceName,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                     `json:"-"`
	XXX_unrecognized     []byte                       `json:"-"`
	XXX_sizecache        int32                        `json:"-"`
}

func (m *SqlScanner_Finding) Reset()         { *m = SqlScanner_Finding{} }
func (m *SqlScanner_Finding) String() string { return proto.CompactTextString(m) }
func (*SqlScanner_Finding) ProtoMessage()    {}
func (*SqlScanner_Finding) Descriptor() ([]byte, []int) {
	return fileDescriptor_42ce1b275ac7c5c9, []int{4, 1}
}

func (m *SqlScanner_Finding) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SqlScanner_Finding.Unmarshal(m, b)
}
func (m *SqlScanner_Finding) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SqlScanner_Finding.Marshal(b, m, deterministic)
}
func (m *SqlScanner_Finding) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SqlScanner_Finding.Merge(m, src)
}
func (m *SqlScanner_Finding) XXX_Size() int {
	return xxx_messageInfo_SqlScanner_Finding.Size(m)
}
func (m *SqlScanner_Finding) XXX_DiscardUnknown() {
	xxx_messageInfo_SqlScanner_Finding.DiscardUnknown(m)
}

var xxx_messageInfo_SqlScanner_Finding proto.InternalMessageInfo

func (m *SqlScanner_Finding) GetSourceProperties() *SqlScanner_SourceProperties {
	if m != nil {
		return m.SourceProperties
	}
	return nil
}

func (m *SqlScanner_Finding) GetCategory() string {
	if m != nil {
		return m.Category
	}
	return ""
}

func (m *SqlScanner_Finding) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

type ContainerScanner struct {
	NotificationConfigName string                    `protobuf:"bytes,1,opt,name=notificationConfigName,proto3" json:"notificationConfigName,omitempty"`
	Finding                *ContainerScanner_Finding `protobuf:"bytes,2,opt,name=finding,proto3" json:"finding,omitempty"`
	XXX_NoUnkeyedLiteral   struct{}                  `json:"-"`
	XXX_unrecognized       []byte                    `json:"-"`
	XXX_sizecache          int32                     `json:"-"`
}

func (m *ContainerScanner) Reset()         { *m = ContainerScanner{} }
func (m *ContainerScanner) String() string { return proto.CompactTextString(m) }
func (*ContainerScanner) ProtoMessage()    {}
func (*ContainerScanner) Descriptor() ([]byte, []int) {
	return fileDescriptor_42ce1b275ac7c5c9, []int{5}
}

func (m *ContainerScanner) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ContainerScanner.Unmarshal(m, b)
}
func (m *ContainerScanner) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ContainerScanner.Marshal(b, m, deterministic)
}
func (m *ContainerScanner) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ContainerScanner.Merge(m, src)
}
func (m *ContainerScanner) XXX_Size() int {
	return xxx_messageInfo_ContainerScanner.Size(m)
}
func (m *ContainerScanner) XXX_DiscardUnknown() {
	xxx_messageInfo_ContainerScanner.DiscardUnknown(m)
}

var xxx_messageInfo_ContainerScanner proto.InternalMessageInfo

func (m *ContainerScanner) GetNotificationConfigName() string {
	if m != nil {
		return m.NotificationConfigName
	}
	return ""
}

func (m *ContainerScanner) GetFinding() *ContainerScanner_Finding {
	if m != nil {
		return m.Finding
	}
	return nil
}

type ContainerScanner_SourceProperties struct {
	ProjectID            string   `protobuf:"bytes,1,opt,name=projectID,proto3" json:"projectID,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ContainerScanner_SourceProperties) Reset()         { *m = ContainerScanner_SourceProperties{} }
func (m *ContainerScanner_SourceProperties) String() string { return proto.CompactTextString(m) }
func (*ContainerScanner_SourceProperties) ProtoMessage()    {}
func (*ContainerScanner_SourceProperties) Descriptor() ([]byte, []int) {
	return fileDescriptor_42ce1b275ac7c5c9, []int{5, 0}
}

func (m *ContainerScanner_SourceProperties) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ContainerScanner_SourceProperties.Unmarshal(m, b)
}
func (m *ContainerScanner_SourceProperties) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ContainerScanner_SourceProperties.Marshal(b, m, deterministic)
}
func (m *ContainerScanner_SourceProperties) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ContainerScanner_SourceProperties.Merge(m, src)
}
func (m *ContainerScanner_SourceProperties) XXX_Size() int {
	return xxx_messageInfo_ContainerScanner_SourceProperties.Size(m)
}
func (m *ContainerScanner_SourceProperties) XXX_DiscardUnknown() {
	xxx_messageInfo_ContainerScanner_SourceProperties.DiscardUnknown(m)
}

var xxx_messageInfo_ContainerScanner_SourceProperties proto.InternalMessageInfo

func (m *ContainerScanner_SourceProperties) GetProjectID() string {
	if m != nil {
		return m.ProjectID
	}
	return ""
}

type ContainerScanner_Finding struct {
	SourceProperties     *ContainerScanner_SourceProperties `protobuf:"bytes,1,opt,name=sourceProperties,proto3" json:"sourceProperties,omitempty"`
	Category             string                             `protobuf:"bytes,2,opt,name=category,proto3" json:"category,omitempty"`
	ResourceName         string                             `protobuf:"bytes,3,opt,name=resourceName,proto3" json:"resourceName,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                           `json:"-"`
	XXX_unrecognized     []byte                             `json:"-"`
	XXX_sizecache        int32                              `json:"-"`
}

func (m *ContainerScanner_Finding) Reset()         { *m = ContainerScanner_Finding{} }
func (m *ContainerScanner_Finding) String() string { return proto.CompactTextString(m) }
func (*ContainerScanner_Finding) ProtoMessage()    {}
func (*ContainerScanner_Finding) Descriptor() ([]byte, []int) {
	return fileDescriptor_42ce1b275ac7c5c9, []int{5, 1}
}

func (m *ContainerScanner_Finding) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ContainerScanner_Finding.Unmarshal(m, b)
}
func (m *ContainerScanner_Finding) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ContainerScanner_Finding.Marshal(b, m, deterministic)
}
func (m *ContainerScanner_Finding) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ContainerScanner_Finding.Merge(m, src)
}
func (m *ContainerScanner_Finding) XXX_Size() int {
	return xxx_messageInfo_ContainerScanner_Finding.Size(m)
}
func (m *ContainerScanner_Finding) XXX_DiscardUnknown() {
	xxx_messageInfo_ContainerScanner_Finding.DiscardUnknown(m)
}

var xxx_messageInfo_ContainerScanner_Finding proto.InternalMessageInfo

func (m *ContainerScanner_Finding) GetSourceProperties() *ContainerScanner_SourceProperties {
	if m != nil {
		return m.SourceProperties
	}
	return nil
}

func (m *ContainerScanner_Finding) GetCategory() string {
	if m != nil {
		return m.Category
	}
	return ""
}

func (m *ContainerScanner_Finding) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

func init() {
	proto.RegisterType((*StorageScanner)(nil), "StorageScanner")
	proto.RegisterType((*StorageScanner_SourceProperties)(nil), "StorageScanner.SourceProperties")
	proto.RegisterType((*StorageScanner_Finding)(nil), "StorageScanner.Finding")
	proto.RegisterType((*FirewallScanner)(nil), "FirewallScanner")
	proto.RegisterType((*FirewallScanner_SourceProperties)(nil), "FirewallScanner.SourceProperties")
	proto.RegisterType((*FirewallScanner_Finding)(nil), "FirewallScanner.Finding")
	proto.RegisterType((*ComputeInstanceScanner)(nil), "ComputeInstanceScanner")
	proto.RegisterType((*ComputeInstanceScanner_SourceProperties)(nil), "ComputeInstanceScanner.SourceProperties")
	proto.RegisterType((*ComputeInstanceScanner_Finding)(nil), "ComputeInstanceScanner.Finding")
	proto.RegisterType((*IamScanner)(nil), "IamScanner")
	proto.RegisterType((*IamScanner_SourceProperties)(nil), "IamScanner.SourceProperties")
	proto.RegisterType((*IamScanner_Finding)(nil), "IamScanner.Finding")
	proto.RegisterType((*SqlScanner)(nil), "SqlScanner")
	proto.RegisterType((*SqlScanner_SourceProperties)(nil), "SqlScanner.SourceProperties")
	proto.RegisterType((*SqlScanner_Finding)(nil), "SqlScanner.Finding")
	proto.RegisterType((*ContainerScanner)(nil), "ContainerScanner")
	proto.RegisterType((*ContainerScanner_SourceProperties)(nil), "ContainerScanner.SourceProperties")
	proto.RegisterType((*ContainerScanner_Finding)(nil), "ContainerScanner.Finding")
}

func init() { proto.RegisterFile("sha/protos/sha.proto", fileDescriptor_42ce1b275ac7c5c9) }

var fileDescriptor_42ce1b275ac7c5c9 = []byte{
	// 512 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xbc, 0x96, 0x41, 0x6b, 0xd4, 0x40,
	0x14, 0xc7, 0x49, 0x56, 0x5d, 0xfb, 0x56, 0xea, 0x3a, 0x4a, 0x8d, 0xa1, 0xe0, 0x9a, 0x83, 0xec,
	0x41, 0x53, 0xdd, 0x82, 0xe0, 0x79, 0x4b, 0x31, 0xa0, 0x45, 0xb2, 0x3d, 0x0b, 0x63, 0xf6, 0x25,
	0x1d, 0xc9, 0xce, 0xc4, 0xc9, 0xd4, 0xe2, 0xe7, 0xf0, 0xa0, 0x9e, 0xfc, 0x20, 0xde, 0x44, 0xf0,
	0xe4, 0x47, 0x10, 0xbf, 0x8a, 0x38, 0x9b, 0xba, 0xd9, 0x19, 0x03, 0x5d, 0xd2, 0xee, 0x2d, 0xf3,
	0xde, 0xbc, 0xf7, 0x9f, 0xf7, 0xfb, 0xcf, 0x40, 0xe0, 0x56, 0x79, 0x44, 0x77, 0x0a, 0x29, 0x94,
	0x28, 0x77, 0xca, 0x23, 0x1a, 0xea, 0xcf, 0xe0, 0x87, 0x0b, 0x9b, 0x13, 0x25, 0x24, 0xcd, 0x70,
	0x92, 0x50, 0xce, 0x51, 0x92, 0x27, 0xb0, 0xc5, 0x85, 0x62, 0x29, 0x4b, 0xa8, 0x62, 0x82, 0x8f,
	0x05, 0x4f, 0x59, 0x76, 0x40, 0x67, 0xe8, 0x39, 0x03, 0x67, 0xb8, 0x11, 0x37, 0x64, 0xc9, 0x63,
	0xe8, 0xa6, 0x8c, 0x4f, 0x19, 0xcf, 0x3c, 0x77, 0xe0, 0x0c, 0x7b, 0xa3, 0xdb, 0xe1, 0x72, 0xe7,
	0x70, 0x7f, 0x9e, 0x8e, 0x4f, 0xf7, 0xf9, 0x8f, 0xa0, 0x3f, 0x11, 0xc7, 0x32, 0xc1, 0x97, 0x52,
	0x14, 0x28, 0x15, 0xc3, 0x92, 0x6c, 0xc3, 0x46, 0x21, 0xc5, 0x1b, 0x4c, 0x54, 0x34, 0xad, 0x14,
	0x17, 0x01, 0xff, 0xa3, 0x03, 0xdd, 0xaa, 0x0d, 0x79, 0x0e, 0xfd, 0xd2, 0xa8, 0xd6, 0x05, 0xbd,
	0xd1, 0xc0, 0x54, 0x36, 0x55, 0x62, 0xab, 0x92, 0x04, 0x70, 0x4d, 0xe2, 0x3c, 0xaa, 0x87, 0x75,
	0xb5, 0xf4, 0x52, 0x8c, 0xf8, 0x70, 0x35, 0xa1, 0x0a, 0x33, 0x21, 0xdf, 0x7b, 0x1d, 0x9d, 0xff,
	0xb7, 0x0e, 0x7e, 0x75, 0xe0, 0xfa, 0x3e, 0x93, 0x78, 0x42, 0xf3, 0xbc, 0x2d, 0xca, 0x91, 0x89,
	0xd2, 0x0b, 0x8d, 0xd6, 0x36, 0xcb, 0x6f, 0xce, 0xaa, 0x30, 0x89, 0x07, 0x5d, 0x9a, 0xe7, 0xe2,
	0x04, 0xa7, 0xd5, 0xb4, 0xa7, 0x4b, 0x72, 0x1f, 0x36, 0xab, 0xcf, 0xa8, 0x88, 0x29, 0xcf, 0xb0,
	0x1a, 0xd7, 0x88, 0x92, 0x07, 0x70, 0x83, 0x26, 0x8a, 0xbd, 0xd3, 0x03, 0x1c, 0x4a, 0x96, 0x65,
	0x28, 0xbd, 0x4b, 0x7a, 0xab, 0x9d, 0x20, 0x03, 0xe8, 0xcd, 0x61, 0xce, 0x5b, 0x5e, 0xd6, 0xfb,
	0xea, 0x21, 0xff, 0x53, 0xcd, 0xde, 0x17, 0x8d, 0xf6, 0xde, 0xb3, 0x68, 0x9c, 0xc1, 0xdf, 0xba,
	0x77, 0xee, 0xb2, 0x77, 0x96, 0xf7, 0x1d, 0xdb, 0xfb, 0xe0, 0xb7, 0x0b, 0x5b, 0x63, 0x31, 0x2b,
	0x8e, 0x15, 0x46, 0xbc, 0x54, 0x94, 0x27, 0xad, 0x5f, 0xcc, 0x53, 0xd3, 0xe6, 0xbb, 0xe1, 0xff,
	0x15, 0x56, 0x7e, 0x39, 0x7b, 0xa6, 0xd9, 0x7b, 0xfe, 0x97, 0x1a, 0xda, 0xc3, 0x46, 0xb4, 0xc3,
	0xa6, 0x13, 0xac, 0x81, 0xf0, 0x77, 0x17, 0x20, 0xa2, 0xb3, 0xb6, 0x54, 0x1f, 0x9a, 0x54, 0x6f,
	0x86, 0x8b, 0xae, 0x36, 0xc9, 0x57, 0xab, 0x92, 0xfc, 0x7b, 0xe9, 0x45, 0x9a, 0xa2, 0x2e, 0x8f,
	0xe8, 0x2c, 0x16, 0x39, 0x96, 0xd5, 0xc0, 0x76, 0xc2, 0x17, 0x0b, 0xec, 0xcf, 0x1a, 0xb1, 0x6f,
	0xd7, 0x8f, 0xd8, 0x0e, 0x75, 0xf0, 0xd5, 0x05, 0x98, 0xbc, 0xcd, 0x2f, 0x00, 0xe3, 0xa2, 0xeb,
	0x79, 0x5c, 0xc8, 0x0f, 0xce, 0xd9, 0xc8, 0xd4, 0x54, 0xd7, 0x70, 0x09, 0x7f, 0xba, 0xd0, 0x1f,
	0x0b, 0xae, 0x28, 0xe3, 0x28, 0xdb, 0x32, 0xdc, 0x35, 0x19, 0xde, 0x09, 0xcd, 0xde, 0xe7, 0x41,
	0xf2, 0x73, 0x8d, 0xe4, 0x41, 0x23, 0xc9, 0xc0, 0xd6, 0xbe, 0x78, 0x9e, 0xaf, 0xaf, 0xe8, 0xff,
	0x8c, 0xdd, 0x3f, 0x01, 0x00, 0x00, 0xff, 0xff, 0x99, 0x2c, 0x78, 0x65, 0x7f, 0x08, 0x00, 0x00,
}
