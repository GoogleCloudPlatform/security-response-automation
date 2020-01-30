package storagescanner

import (
	"encoding/json"
	"strings"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gcs/closebucket"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gcs/enablebucketonlypolicy"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/sha"
)

// Finding represents this finding.
type Finding struct {
	storageScanner *pb.StorageScanner
}

// Category returns the category of the finding.
func (f *Finding) Category() string {
	if f.storageScanner.GetFinding().GetSourceProperties().GetScannerName() != "STORAGE_SCANNER" {
		return ""
	}
	return strings.ToLower(f.storageScanner.GetFinding().GetCategory())
}

// New returns a new finding.
func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.storageScanner); err != nil {
		return nil, err
	}
	return &f, nil
}

// EnableBucketOnlyPolicy returns values for the enable bucket only policy automation.
func (f *Finding) EnableBucketOnlyPolicy() *enablebucketonlypolicy.Values {
	return &enablebucketonlypolicy.Values{
		ProjectID:  f.storageScanner.GetFinding().GetSourceProperties().GetProjectId(),
		BucketName: sha.BucketName(f.storageScanner.GetFinding().GetResourceName()),
		Hash:       f.storageScanner.GetFinding().GetSecurityMarks().GetMarks().GetSraRemediated(),
		Name:       f.storageScanner.GetFinding().GetName(),
	}
}

// CloseBucket returns values for the close bucket automation.
func (f *Finding) CloseBucket() *closebucket.Values {
	return &closebucket.Values{
		ProjectID:  f.storageScanner.GetFinding().GetSourceProperties().GetProjectId(),
		BucketName: sha.BucketName(f.storageScanner.GetFinding().GetResourceName()),
		Hash:       f.storageScanner.GetFinding().GetSecurityMarks().GetMarks().GetSraRemediated(),
		Name:       f.storageScanner.GetFinding().GetName(),
	}
}

// StringToBeHashed returns the string that will be used to generate the mark hash finding.
func (f *Finding) StringToBeHashed() string {
	return f.storageScanner.GetFinding().GetEventTime() + f.storageScanner.GetFinding().GetName()
}

// SraRemediated returns the sraRemediate mark of the finding.
func (f *Finding) SraRemediated() string {
	return f.storageScanner.GetFinding().GetSecurityMarks().GetMarks().GetSraRemediated()
}

// Deserialize deserializes the finding in object.
func (f *Finding) Deserialize(b []byte) error {
	if err := json.Unmarshal(b, &f.storageScanner); err != nil {
		return err
	}
	return nil
}
