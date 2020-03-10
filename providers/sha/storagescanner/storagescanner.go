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
	StorageScanner *pb.StorageScanner
}

// Name returns the rule name of the finding.
func (f *Finding) Name(b []byte) string {
	var finding pb.StorageScanner
	if err := json.Unmarshal(b, &finding); err != nil {
		return ""
	}
	if finding.GetFinding().GetSourceProperties().GetScannerName() != "STORAGE_SCANNER" {
		return ""
	}
	return strings.ToLower(finding.GetFinding().GetCategory())
}

// New returns a new finding.
func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.StorageScanner); err != nil {
		return nil, err
	}
	return &f, nil
}

// EnableBucketOnlyPolicy returns values for the enable bucket only policy automation.
func (f *Finding) EnableBucketOnlyPolicy() *enablebucketonlypolicy.Values {
	return &enablebucketonlypolicy.Values{
		ProjectID:  f.StorageScanner.GetFinding().GetSourceProperties().GetProjectId(),
		BucketName: sha.BucketName(f.StorageScanner.GetFinding().GetResourceName()),
	}
}

// CloseBucket returns values for the close bucket automation.
func (f *Finding) CloseBucket() *closebucket.Values {
	return &closebucket.Values{
		ProjectID:  f.StorageScanner.GetFinding().GetSourceProperties().GetProjectId(),
		BucketName: sha.BucketName(f.StorageScanner.GetFinding().GetResourceName()),
	}
}
