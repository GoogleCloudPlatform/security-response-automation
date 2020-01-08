// Code generated by protoc-gen-go. DO NOT EDIT.
// source: sha/protos/sha.proto

/*
Package sha is a generated protocol buffer package.

It is generated from these files:
	sha/protos/sha.proto

It has these top-level messages:
	StorageScanner
	FirewallScanner
	ComputeInstanceScanner
	DatasetScanner
	IamScanner
	SqlScanner
	ContainerScanner
	LoggingScanner
*/
package sha

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type StorageScanner struct {
	NotificationConfigName string                  `protobuf:"bytes,1,opt,name=notificationConfigName" json:"notificationConfigName,omitempty"`
	Finding                *StorageScanner_Finding `protobuf:"bytes,2,opt,name=finding" json:"finding,omitempty"`
}

func (m *StorageScanner) Reset()                    { *m = StorageScanner{} }
func (m *StorageScanner) String() string            { return proto.CompactTextString(m) }
func (*StorageScanner) ProtoMessage()               {}
func (*StorageScanner) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

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
	ProjectId   string `protobuf:"bytes,1,opt,name=projectId" json:"projectId,omitempty"`
	ScannerName string `protobuf:"bytes,2,opt,name=ScannerName,json=scannerName" json:"ScannerName,omitempty"`
}

func (m *StorageScanner_SourceProperties) Reset()         { *m = StorageScanner_SourceProperties{} }
func (m *StorageScanner_SourceProperties) String() string { return proto.CompactTextString(m) }
func (*StorageScanner_SourceProperties) ProtoMessage()    {}
func (*StorageScanner_SourceProperties) Descriptor() ([]byte, []int) {
	return fileDescriptor0, []int{0, 0}
}

func (m *StorageScanner_SourceProperties) GetProjectId() string {
	if m != nil {
		return m.ProjectId
	}
	return ""
}

func (m *StorageScanner_SourceProperties) GetScannerName() string {
	if m != nil {
		return m.ScannerName
	}
	return ""
}

type StorageScanner_Finding struct {
	SourceProperties *StorageScanner_SourceProperties `protobuf:"bytes,1,opt,name=sourceProperties" json:"sourceProperties,omitempty"`
	ResourceName     string                           `protobuf:"bytes,2,opt,name=resourceName" json:"resourceName,omitempty"`
	Category         string                           `protobuf:"bytes,3,opt,name=category" json:"category,omitempty"`
	State            string                           `protobuf:"bytes,4,opt,name=state" json:"state,omitempty"`
}

func (m *StorageScanner_Finding) Reset()                    { *m = StorageScanner_Finding{} }
func (m *StorageScanner_Finding) String() string            { return proto.CompactTextString(m) }
func (*StorageScanner_Finding) ProtoMessage()               {}
func (*StorageScanner_Finding) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0, 1} }

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

func (m *StorageScanner_Finding) GetState() string {
	if m != nil {
		return m.State
	}
	return ""
}

type FirewallScanner struct {
	NotificationConfigName string                   `protobuf:"bytes,1,opt,name=notificationConfigName" json:"notificationConfigName,omitempty"`
	Finding                *FirewallScanner_Finding `protobuf:"bytes,2,opt,name=finding" json:"finding,omitempty"`
}

func (m *FirewallScanner) Reset()                    { *m = FirewallScanner{} }
func (m *FirewallScanner) String() string            { return proto.CompactTextString(m) }
func (*FirewallScanner) ProtoMessage()               {}
func (*FirewallScanner) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

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
	ProjectId         string `protobuf:"bytes,1,opt,name=projectId" json:"projectId,omitempty"`
	Allowed           string `protobuf:"bytes,2,opt,name=allowed" json:"allowed,omitempty"`
	AllowedIpRange    string `protobuf:"bytes,3,opt,name=allowedIpRange" json:"allowedIpRange,omitempty"`
	ActivationTrigger string `protobuf:"bytes,4,opt,name=activationTrigger" json:"activationTrigger,omitempty"`
	SourceRange       string `protobuf:"bytes,5,opt,name=sourceRange" json:"sourceRange,omitempty"`
	ScannerName       string `protobuf:"bytes,6,opt,name=ScannerName,json=scannerName" json:"ScannerName,omitempty"`
}

func (m *FirewallScanner_SourceProperties) Reset()         { *m = FirewallScanner_SourceProperties{} }
func (m *FirewallScanner_SourceProperties) String() string { return proto.CompactTextString(m) }
func (*FirewallScanner_SourceProperties) ProtoMessage()    {}
func (*FirewallScanner_SourceProperties) Descriptor() ([]byte, []int) {
	return fileDescriptor0, []int{1, 0}
}

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

func (m *FirewallScanner_SourceProperties) GetScannerName() string {
	if m != nil {
		return m.ScannerName
	}
	return ""
}

type FirewallScanner_Finding struct {
	SourceProperties *FirewallScanner_SourceProperties `protobuf:"bytes,1,opt,name=sourceProperties" json:"sourceProperties,omitempty"`
	Category         string                            `protobuf:"bytes,2,opt,name=category" json:"category,omitempty"`
	ResourceName     string                            `protobuf:"bytes,3,opt,name=resourceName" json:"resourceName,omitempty"`
	State            string                            `protobuf:"bytes,4,opt,name=state" json:"state,omitempty"`
}

func (m *FirewallScanner_Finding) Reset()                    { *m = FirewallScanner_Finding{} }
func (m *FirewallScanner_Finding) String() string            { return proto.CompactTextString(m) }
func (*FirewallScanner_Finding) ProtoMessage()               {}
func (*FirewallScanner_Finding) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1, 1} }

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

func (m *FirewallScanner_Finding) GetState() string {
	if m != nil {
		return m.State
	}
	return ""
}

type ComputeInstanceScanner struct {
	NotificationConfigName string                          `protobuf:"bytes,1,opt,name=notificationConfigName" json:"notificationConfigName,omitempty"`
	Finding                *ComputeInstanceScanner_Finding `protobuf:"bytes,2,opt,name=finding" json:"finding,omitempty"`
}

func (m *ComputeInstanceScanner) Reset()                    { *m = ComputeInstanceScanner{} }
func (m *ComputeInstanceScanner) String() string            { return proto.CompactTextString(m) }
func (*ComputeInstanceScanner) ProtoMessage()               {}
func (*ComputeInstanceScanner) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

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
	ProjectID   string `protobuf:"bytes,1,opt,name=projectID" json:"projectID,omitempty"`
	ScannerName string `protobuf:"bytes,2,opt,name=ScannerName,json=scannerName" json:"ScannerName,omitempty"`
}

func (m *ComputeInstanceScanner_SourceProperties) Reset() {
	*m = ComputeInstanceScanner_SourceProperties{}
}
func (m *ComputeInstanceScanner_SourceProperties) String() string { return proto.CompactTextString(m) }
func (*ComputeInstanceScanner_SourceProperties) ProtoMessage()    {}
func (*ComputeInstanceScanner_SourceProperties) Descriptor() ([]byte, []int) {
	return fileDescriptor0, []int{2, 0}
}

func (m *ComputeInstanceScanner_SourceProperties) GetProjectID() string {
	if m != nil {
		return m.ProjectID
	}
	return ""
}

func (m *ComputeInstanceScanner_SourceProperties) GetScannerName() string {
	if m != nil {
		return m.ScannerName
	}
	return ""
}

type ComputeInstanceScanner_Finding struct {
	SourceProperties *ComputeInstanceScanner_SourceProperties `protobuf:"bytes,1,opt,name=sourceProperties" json:"sourceProperties,omitempty"`
	Category         string                                   `protobuf:"bytes,2,opt,name=category" json:"category,omitempty"`
	ResourceName     string                                   `protobuf:"bytes,3,opt,name=resourceName" json:"resourceName,omitempty"`
	State            string                                   `protobuf:"bytes,4,opt,name=state" json:"state,omitempty"`
}

func (m *ComputeInstanceScanner_Finding) Reset()         { *m = ComputeInstanceScanner_Finding{} }
func (m *ComputeInstanceScanner_Finding) String() string { return proto.CompactTextString(m) }
func (*ComputeInstanceScanner_Finding) ProtoMessage()    {}
func (*ComputeInstanceScanner_Finding) Descriptor() ([]byte, []int) {
	return fileDescriptor0, []int{2, 1}
}

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

func (m *ComputeInstanceScanner_Finding) GetState() string {
	if m != nil {
		return m.State
	}
	return ""
}

type DatasetScanner struct {
	NotificationConfigName string                  `protobuf:"bytes,1,opt,name=notificationConfigName" json:"notificationConfigName,omitempty"`
	Finding                *DatasetScanner_Finding `protobuf:"bytes,2,opt,name=finding" json:"finding,omitempty"`
}

func (m *DatasetScanner) Reset()                    { *m = DatasetScanner{} }
func (m *DatasetScanner) String() string            { return proto.CompactTextString(m) }
func (*DatasetScanner) ProtoMessage()               {}
func (*DatasetScanner) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *DatasetScanner) GetNotificationConfigName() string {
	if m != nil {
		return m.NotificationConfigName
	}
	return ""
}

func (m *DatasetScanner) GetFinding() *DatasetScanner_Finding {
	if m != nil {
		return m.Finding
	}
	return nil
}

type DatasetScanner_SourceProperties struct {
	ProjectID   string `protobuf:"bytes,1,opt,name=projectID" json:"projectID,omitempty"`
	ScannerName string `protobuf:"bytes,2,opt,name=ScannerName,json=scannerName" json:"ScannerName,omitempty"`
}

func (m *DatasetScanner_SourceProperties) Reset()         { *m = DatasetScanner_SourceProperties{} }
func (m *DatasetScanner_SourceProperties) String() string { return proto.CompactTextString(m) }
func (*DatasetScanner_SourceProperties) ProtoMessage()    {}
func (*DatasetScanner_SourceProperties) Descriptor() ([]byte, []int) {
	return fileDescriptor0, []int{3, 0}
}

func (m *DatasetScanner_SourceProperties) GetProjectID() string {
	if m != nil {
		return m.ProjectID
	}
	return ""
}

func (m *DatasetScanner_SourceProperties) GetScannerName() string {
	if m != nil {
		return m.ScannerName
	}
	return ""
}

type DatasetScanner_Finding struct {
	SourceProperties *DatasetScanner_SourceProperties `protobuf:"bytes,1,opt,name=sourceProperties" json:"sourceProperties,omitempty"`
	Category         string                           `protobuf:"bytes,2,opt,name=category" json:"category,omitempty"`
	ResourceName     string                           `protobuf:"bytes,3,opt,name=resourceName" json:"resourceName,omitempty"`
	State            string                           `protobuf:"bytes,4,opt,name=state" json:"state,omitempty"`
}

func (m *DatasetScanner_Finding) Reset()                    { *m = DatasetScanner_Finding{} }
func (m *DatasetScanner_Finding) String() string            { return proto.CompactTextString(m) }
func (*DatasetScanner_Finding) ProtoMessage()               {}
func (*DatasetScanner_Finding) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3, 1} }

func (m *DatasetScanner_Finding) GetSourceProperties() *DatasetScanner_SourceProperties {
	if m != nil {
		return m.SourceProperties
	}
	return nil
}

func (m *DatasetScanner_Finding) GetCategory() string {
	if m != nil {
		return m.Category
	}
	return ""
}

func (m *DatasetScanner_Finding) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

func (m *DatasetScanner_Finding) GetState() string {
	if m != nil {
		return m.State
	}
	return ""
}

type IamScanner struct {
	NotificationConfigName string              `protobuf:"bytes,1,opt,name=notificationConfigName" json:"notificationConfigName,omitempty"`
	Finding                *IamScanner_Finding `protobuf:"bytes,2,opt,name=finding" json:"finding,omitempty"`
}

func (m *IamScanner) Reset()                    { *m = IamScanner{} }
func (m *IamScanner) String() string            { return proto.CompactTextString(m) }
func (*IamScanner) ProtoMessage()               {}
func (*IamScanner) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

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
	ProjectID         string `protobuf:"bytes,1,opt,name=projectID" json:"projectID,omitempty"`
	OffendingIamRoles string `protobuf:"bytes,2,opt,name=offendingIamRoles" json:"offendingIamRoles,omitempty"`
	ScannerName       string `protobuf:"bytes,3,opt,name=ScannerName,json=scannerName" json:"ScannerName,omitempty"`
}

func (m *IamScanner_SourceProperties) Reset()                    { *m = IamScanner_SourceProperties{} }
func (m *IamScanner_SourceProperties) String() string            { return proto.CompactTextString(m) }
func (*IamScanner_SourceProperties) ProtoMessage()               {}
func (*IamScanner_SourceProperties) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4, 0} }

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

func (m *IamScanner_SourceProperties) GetScannerName() string {
	if m != nil {
		return m.ScannerName
	}
	return ""
}

type IamScanner_Finding struct {
	SourceProperties *IamScanner_SourceProperties `protobuf:"bytes,1,opt,name=sourceProperties" json:"sourceProperties,omitempty"`
	Category         string                       `protobuf:"bytes,2,opt,name=category" json:"category,omitempty"`
	Parent           string                       `protobuf:"bytes,3,opt,name=parent" json:"parent,omitempty"`
	State            string                       `protobuf:"bytes,4,opt,name=state" json:"state,omitempty"`
	ResourceName     string                       `protobuf:"bytes,5,opt,name=resourceName" json:"resourceName,omitempty"`
}

func (m *IamScanner_Finding) Reset()                    { *m = IamScanner_Finding{} }
func (m *IamScanner_Finding) String() string            { return proto.CompactTextString(m) }
func (*IamScanner_Finding) ProtoMessage()               {}
func (*IamScanner_Finding) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4, 1} }

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

func (m *IamScanner_Finding) GetParent() string {
	if m != nil {
		return m.Parent
	}
	return ""
}

func (m *IamScanner_Finding) GetState() string {
	if m != nil {
		return m.State
	}
	return ""
}

func (m *IamScanner_Finding) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

type SqlScanner struct {
	NotificationConfigName string              `protobuf:"bytes,1,opt,name=notificationConfigName" json:"notificationConfigName,omitempty"`
	Finding                *SqlScanner_Finding `protobuf:"bytes,2,opt,name=finding" json:"finding,omitempty"`
}

func (m *SqlScanner) Reset()                    { *m = SqlScanner{} }
func (m *SqlScanner) String() string            { return proto.CompactTextString(m) }
func (*SqlScanner) ProtoMessage()               {}
func (*SqlScanner) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

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
	ProjectID   string `protobuf:"bytes,1,opt,name=projectID" json:"projectID,omitempty"`
	ScannerName string `protobuf:"bytes,2,opt,name=ScannerName,json=scannerName" json:"ScannerName,omitempty"`
}

func (m *SqlScanner_SourceProperties) Reset()                    { *m = SqlScanner_SourceProperties{} }
func (m *SqlScanner_SourceProperties) String() string            { return proto.CompactTextString(m) }
func (*SqlScanner_SourceProperties) ProtoMessage()               {}
func (*SqlScanner_SourceProperties) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5, 0} }

func (m *SqlScanner_SourceProperties) GetProjectID() string {
	if m != nil {
		return m.ProjectID
	}
	return ""
}

func (m *SqlScanner_SourceProperties) GetScannerName() string {
	if m != nil {
		return m.ScannerName
	}
	return ""
}

type SqlScanner_Finding struct {
	SourceProperties *SqlScanner_SourceProperties `protobuf:"bytes,1,opt,name=sourceProperties" json:"sourceProperties,omitempty"`
	Category         string                       `protobuf:"bytes,2,opt,name=category" json:"category,omitempty"`
	ResourceName     string                       `protobuf:"bytes,3,opt,name=resourceName" json:"resourceName,omitempty"`
	State            string                       `protobuf:"bytes,4,opt,name=state" json:"state,omitempty"`
}

func (m *SqlScanner_Finding) Reset()                    { *m = SqlScanner_Finding{} }
func (m *SqlScanner_Finding) String() string            { return proto.CompactTextString(m) }
func (*SqlScanner_Finding) ProtoMessage()               {}
func (*SqlScanner_Finding) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5, 1} }

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

func (m *SqlScanner_Finding) GetState() string {
	if m != nil {
		return m.State
	}
	return ""
}

type ContainerScanner struct {
	NotificationConfigName string                    `protobuf:"bytes,1,opt,name=notificationConfigName" json:"notificationConfigName,omitempty"`
	Finding                *ContainerScanner_Finding `protobuf:"bytes,2,opt,name=finding" json:"finding,omitempty"`
}

func (m *ContainerScanner) Reset()                    { *m = ContainerScanner{} }
func (m *ContainerScanner) String() string            { return proto.CompactTextString(m) }
func (*ContainerScanner) ProtoMessage()               {}
func (*ContainerScanner) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

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
	ProjectID   string `protobuf:"bytes,1,opt,name=projectID" json:"projectID,omitempty"`
	ScannerName string `protobuf:"bytes,2,opt,name=ScannerName,json=scannerName" json:"ScannerName,omitempty"`
}

func (m *ContainerScanner_SourceProperties) Reset()         { *m = ContainerScanner_SourceProperties{} }
func (m *ContainerScanner_SourceProperties) String() string { return proto.CompactTextString(m) }
func (*ContainerScanner_SourceProperties) ProtoMessage()    {}
func (*ContainerScanner_SourceProperties) Descriptor() ([]byte, []int) {
	return fileDescriptor0, []int{6, 0}
}

func (m *ContainerScanner_SourceProperties) GetProjectID() string {
	if m != nil {
		return m.ProjectID
	}
	return ""
}

func (m *ContainerScanner_SourceProperties) GetScannerName() string {
	if m != nil {
		return m.ScannerName
	}
	return ""
}

type ContainerScanner_Finding struct {
	SourceProperties *ContainerScanner_SourceProperties `protobuf:"bytes,1,opt,name=sourceProperties" json:"sourceProperties,omitempty"`
	Category         string                             `protobuf:"bytes,2,opt,name=category" json:"category,omitempty"`
	ResourceName     string                             `protobuf:"bytes,3,opt,name=resourceName" json:"resourceName,omitempty"`
	State            string                             `protobuf:"bytes,4,opt,name=state" json:"state,omitempty"`
}

func (m *ContainerScanner_Finding) Reset()                    { *m = ContainerScanner_Finding{} }
func (m *ContainerScanner_Finding) String() string            { return proto.CompactTextString(m) }
func (*ContainerScanner_Finding) ProtoMessage()               {}
func (*ContainerScanner_Finding) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6, 1} }

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

func (m *ContainerScanner_Finding) GetState() string {
	if m != nil {
		return m.State
	}
	return ""
}

type LoggingScanner struct {
	NotificationConfigName string                  `protobuf:"bytes,1,opt,name=notificationConfigName" json:"notificationConfigName,omitempty"`
	Finding                *LoggingScanner_Finding `protobuf:"bytes,2,opt,name=finding" json:"finding,omitempty"`
}

func (m *LoggingScanner) Reset()                    { *m = LoggingScanner{} }
func (m *LoggingScanner) String() string            { return proto.CompactTextString(m) }
func (*LoggingScanner) ProtoMessage()               {}
func (*LoggingScanner) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{7} }

func (m *LoggingScanner) GetNotificationConfigName() string {
	if m != nil {
		return m.NotificationConfigName
	}
	return ""
}

func (m *LoggingScanner) GetFinding() *LoggingScanner_Finding {
	if m != nil {
		return m.Finding
	}
	return nil
}

type LoggingScanner_SourceProperties struct {
	ProjectID   string `protobuf:"bytes,1,opt,name=projectID" json:"projectID,omitempty"`
	ScannerName string `protobuf:"bytes,2,opt,name=ScannerName,json=scannerName" json:"ScannerName,omitempty"`
}

func (m *LoggingScanner_SourceProperties) Reset()         { *m = LoggingScanner_SourceProperties{} }
func (m *LoggingScanner_SourceProperties) String() string { return proto.CompactTextString(m) }
func (*LoggingScanner_SourceProperties) ProtoMessage()    {}
func (*LoggingScanner_SourceProperties) Descriptor() ([]byte, []int) {
	return fileDescriptor0, []int{7, 0}
}

func (m *LoggingScanner_SourceProperties) GetProjectID() string {
	if m != nil {
		return m.ProjectID
	}
	return ""
}

func (m *LoggingScanner_SourceProperties) GetScannerName() string {
	if m != nil {
		return m.ScannerName
	}
	return ""
}

type LoggingScanner_Finding struct {
	SourceProperties *LoggingScanner_SourceProperties `protobuf:"bytes,1,opt,name=sourceProperties" json:"sourceProperties,omitempty"`
	Category         string                           `protobuf:"bytes,2,opt,name=category" json:"category,omitempty"`
	ResourceName     string                           `protobuf:"bytes,3,opt,name=resourceName" json:"resourceName,omitempty"`
	State            string                           `protobuf:"bytes,4,opt,name=state" json:"state,omitempty"`
}

func (m *LoggingScanner_Finding) Reset()                    { *m = LoggingScanner_Finding{} }
func (m *LoggingScanner_Finding) String() string            { return proto.CompactTextString(m) }
func (*LoggingScanner_Finding) ProtoMessage()               {}
func (*LoggingScanner_Finding) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{7, 1} }

func (m *LoggingScanner_Finding) GetSourceProperties() *LoggingScanner_SourceProperties {
	if m != nil {
		return m.SourceProperties
	}
	return nil
}

func (m *LoggingScanner_Finding) GetCategory() string {
	if m != nil {
		return m.Category
	}
	return ""
}

func (m *LoggingScanner_Finding) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

func (m *LoggingScanner_Finding) GetState() string {
	if m != nil {
		return m.State
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
	proto.RegisterType((*DatasetScanner)(nil), "DatasetScanner")
	proto.RegisterType((*DatasetScanner_SourceProperties)(nil), "DatasetScanner.SourceProperties")
	proto.RegisterType((*DatasetScanner_Finding)(nil), "DatasetScanner.Finding")
	proto.RegisterType((*IamScanner)(nil), "IamScanner")
	proto.RegisterType((*IamScanner_SourceProperties)(nil), "IamScanner.SourceProperties")
	proto.RegisterType((*IamScanner_Finding)(nil), "IamScanner.Finding")
	proto.RegisterType((*SqlScanner)(nil), "SqlScanner")
	proto.RegisterType((*SqlScanner_SourceProperties)(nil), "SqlScanner.SourceProperties")
	proto.RegisterType((*SqlScanner_Finding)(nil), "SqlScanner.Finding")
	proto.RegisterType((*ContainerScanner)(nil), "ContainerScanner")
	proto.RegisterType((*ContainerScanner_SourceProperties)(nil), "ContainerScanner.SourceProperties")
	proto.RegisterType((*ContainerScanner_Finding)(nil), "ContainerScanner.Finding")
	proto.RegisterType((*LoggingScanner)(nil), "LoggingScanner")
	proto.RegisterType((*LoggingScanner_SourceProperties)(nil), "LoggingScanner.SourceProperties")
	proto.RegisterType((*LoggingScanner_Finding)(nil), "LoggingScanner.Finding")
}

func init() { proto.RegisterFile("sha/protos/sha.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 610 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xcc, 0x97, 0xc1, 0x6e, 0xd3, 0x40,
	0x10, 0x86, 0xe5, 0xb8, 0x4d, 0xe8, 0x04, 0x95, 0xd4, 0x54, 0xc1, 0x44, 0x95, 0x08, 0x39, 0xa0,
	0x1c, 0x8a, 0x2b, 0x52, 0x09, 0x89, 0x73, 0xa2, 0x8a, 0x48, 0xa5, 0x42, 0x4e, 0x5f, 0x60, 0x71,
	0x26, 0xee, 0x22, 0x67, 0xd7, 0xac, 0xb7, 0x54, 0xdc, 0xb8, 0xf0, 0x08, 0x88, 0x67, 0xe0, 0x00,
	0x9c, 0xb8, 0x70, 0xe3, 0x5d, 0x78, 0x03, 0x1e, 0x00, 0x54, 0x67, 0x4b, 0x9c, 0xdd, 0x58, 0x4a,
	0x14, 0x25, 0xe6, 0xe6, 0x9d, 0x89, 0xff, 0x1d, 0xff, 0xdf, 0xcc, 0xae, 0x02, 0xfb, 0xc9, 0x05,
	0x39, 0x8a, 0x05, 0x97, 0x3c, 0x39, 0x4a, 0x2e, 0x88, 0x97, 0x3e, 0xb6, 0xfe, 0x94, 0x60, 0x77,
	0x20, 0xb9, 0x20, 0x21, 0x0e, 0x02, 0xc2, 0x18, 0x0a, 0xe7, 0x29, 0xd4, 0x19, 0x97, 0x74, 0x44,
	0x03, 0x22, 0x29, 0x67, 0x5d, 0xce, 0x46, 0x34, 0x3c, 0x23, 0x63, 0x74, 0xad, 0xa6, 0xd5, 0xde,
	0xf1, 0x73, 0xb2, 0xce, 0x13, 0xa8, 0x8c, 0x28, 0x1b, 0x52, 0x16, 0xba, 0xa5, 0xa6, 0xd5, 0xae,
	0x76, 0xee, 0x79, 0xb3, 0xca, 0xde, 0xc9, 0x24, 0xed, 0xdf, 0xfc, 0xae, 0xe1, 0x43, 0x6d, 0xc0,
	0x2f, 0x45, 0x80, 0x2f, 0x05, 0x8f, 0x51, 0x48, 0x8a, 0x89, 0x73, 0x00, 0x3b, 0xb1, 0xe0, 0xaf,
	0x31, 0x90, 0xfd, 0xa1, 0xda, 0x71, 0x1a, 0x70, 0x9a, 0x50, 0x55, 0x6a, 0x69, 0x45, 0xa5, 0x34,
	0x5f, 0x4d, 0xa6, 0xa1, 0xc6, 0x17, 0x0b, 0x2a, 0x6a, 0x23, 0xe7, 0x14, 0x6a, 0x89, 0xa6, 0x9f,
	0x4a, 0x56, 0x3b, 0x4d, 0xbd, 0x36, 0xbd, 0x0e, 0xdf, 0x78, 0xd3, 0x69, 0xc1, 0x6d, 0x81, 0x93,
	0x68, 0x66, 0xf3, 0x99, 0x98, 0xd3, 0x80, 0x5b, 0x01, 0x91, 0x18, 0x72, 0xf1, 0xce, 0xb5, 0xd3,
	0xfc, 0xbf, 0xb5, 0xb3, 0x0f, 0xdb, 0x89, 0x24, 0x12, 0xdd, 0xad, 0x34, 0x31, 0x59, 0xb4, 0x3e,
	0x6e, 0xc1, 0x9d, 0x13, 0x2a, 0xf0, 0x8a, 0x44, 0xd1, 0xaa, 0x08, 0x3a, 0x3a, 0x02, 0xd7, 0xd3,
	0xa4, 0x4d, 0x06, 0xbf, 0xac, 0xa5, 0x21, 0xb8, 0x50, 0x21, 0x51, 0xc4, 0xaf, 0x70, 0xa8, 0x3c,
	0xb8, 0x59, 0x3a, 0x8f, 0x60, 0x57, 0x3d, 0xf6, 0x63, 0x9f, 0xb0, 0x10, 0x95, 0x09, 0x5a, 0xd4,
	0x39, 0x84, 0x3d, 0x12, 0x48, 0xfa, 0x36, 0xfd, 0x80, 0x73, 0x41, 0xc3, 0x10, 0x85, 0xb2, 0xc5,
	0x4c, 0x5c, 0x43, 0x9f, 0x58, 0x3c, 0x91, 0xdc, 0x56, 0xd0, 0xa7, 0x21, 0xbd, 0x2d, 0xca, 0x66,
	0x5b, 0x7c, 0xcd, 0xb4, 0xc5, 0x8b, 0xdc, 0xb6, 0x78, 0x68, 0xf8, 0xb5, 0x40, 0x5f, 0x64, 0x99,
	0x97, 0x34, 0xe6, 0x7a, 0xcf, 0xd8, 0x73, 0x7a, 0x66, 0x7e, 0x5f, 0x7c, 0xb2, 0xa1, 0xde, 0xe5,
	0xe3, 0xf8, 0x52, 0x62, 0x9f, 0x25, 0x92, 0xb0, 0x60, 0xe5, 0x09, 0x7d, 0xa6, 0xb7, 0xc7, 0x03,
	0x6f, 0xfe, 0x0e, 0x4b, 0x4f, 0x6a, 0x4f, 0x6f, 0x92, 0xde, 0x02, 0x93, 0xfa, 0x3d, 0x83, 0xe4,
	0x3c, 0x17, 0x49, 0x3b, 0xaf, 0xc6, 0xc2, 0xc8, 0x5c, 0x9f, 0x99, 0x3d, 0x22, 0x49, 0x82, 0x72,
	0x0d, 0x67, 0xe6, 0xac, 0xf2, 0x66, 0x48, 0x2c, 0x7a, 0x66, 0x6a, 0xb5, 0x15, 0x46, 0xe0, 0x87,
	0x0d, 0xd0, 0x27, 0xe3, 0x55, 0xdd, 0x7f, 0xac, 0xbb, 0x7f, 0xd7, 0x9b, 0xaa, 0x9a, 0xce, 0xbf,
	0xb7, 0x96, 0xb6, 0xfe, 0x10, 0xf6, 0xf8, 0x68, 0x84, 0xe9, 0xfb, 0x7d, 0x32, 0xf6, 0x79, 0x84,
	0x89, 0xf2, 0xc1, 0x4c, 0xe8, 0xa0, 0x6c, 0x13, 0xd4, 0xcf, 0x0c, 0xa8, 0xe7, 0xb9, 0xa0, 0x0e,
	0xb2, 0x9f, 0xb1, 0x22, 0xa4, 0x3a, 0x94, 0x63, 0x22, 0x90, 0x49, 0x55, 0x8e, 0x5a, 0xcd, 0x07,
	0x63, 0x20, 0xdd, 0x36, 0x91, 0xb6, 0x7e, 0x97, 0x00, 0x06, 0x6f, 0xa2, 0x35, 0xc0, 0x9b, 0xaa,
	0x6e, 0x66, 0x6c, 0x3e, 0x2f, 0x48, 0x23, 0x53, 0x57, 0x61, 0x23, 0xf3, 0xc1, 0x86, 0x5a, 0x97,
	0x33, 0x49, 0x28, 0x43, 0xb1, 0xaa, 0xf7, 0xc7, 0xba, 0xf7, 0xf7, 0x3d, 0x5d, 0x7b, 0x33, 0x04,
	0xbe, 0x65, 0x08, 0x9c, 0xe5, 0x12, 0x68, 0x99, 0xd5, 0x15, 0x7a, 0x79, 0x9c, 0xf2, 0x30, 0xa4,
	0x2c, 0x5c, 0xc3, 0xe5, 0x31, 0xab, 0xfc, 0x7f, 0x5d, 0x1e, 0x5a, 0x6d, 0x45, 0x11, 0x78, 0x55,
	0x4e, 0xff, 0xf9, 0x1c, 0xff, 0x0d, 0x00, 0x00, 0xff, 0xff, 0x39, 0x23, 0x71, 0xab, 0x11, 0x0d,
	0x00, 0x00,
}
