package storagescanner

import (
	"encoding/json"
	"fmt"
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
	if err := json.Unmarshal(b, &f.storageScanner); err != nil {
		return nil, err
	}
	if f.AlreadyRemediated() {
		return nil, fmt.Errorf("remediation ignored! Finding already processed and remediated. Security Mark: \"sra-remediated-event-time: %s\"", f.sraRemediated())
	}
	return &f, nil
}

// EnableBucketOnlyPolicy returns values for the enable bucket only policy automation.
func (f *Finding) EnableBucketOnlyPolicy() *enablebucketonlypolicy.Values {
	return &enablebucketonlypolicy.Values{
		ProjectID:  f.storageScanner.GetFinding().GetSourceProperties().GetProjectId(),
		BucketName: sha.BucketName(f.storageScanner.GetFinding().GetResourceName()),
		Mark:       f.storageScanner.GetFinding().GetEventTime(),
		Name:       f.storageScanner.GetFinding().GetName(),
	}
}

// CloseBucket returns values for the close bucket automation.
func (f *Finding) CloseBucket() *closebucket.Values {
	return &closebucket.Values{
		ProjectID:  f.storageScanner.GetFinding().GetSourceProperties().GetProjectId(),
		BucketName: sha.BucketName(f.storageScanner.GetFinding().GetResourceName()),
		Mark:       f.storageScanner.GetFinding().GetEventTime(),
		Name:       f.storageScanner.GetFinding().GetName(),
	}
}

// sraRemediated returns the mark sra-remediated-event-time.
func (f *Finding) sraRemediated() string {
	marks := f.storageScanner.GetFinding().GetSecurityMarks().GetMarks()
	if marks != nil {
		return marks["sra-remediated-event-time"]
	}
	return ""
}

// AlreadyRemediated returns if the finding was remediated before or not.
func (f *Finding) AlreadyRemediated() bool {
	return f.sraRemediated() == f.storageScanner.GetFinding().GetEventTime()
}
