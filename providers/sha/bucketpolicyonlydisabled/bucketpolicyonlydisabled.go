package bucketpolicyonlydisabled

import (
	"encoding/json"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gcs/enablebucketonlypolicy"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/sha"
)

// Automation defines the configuration for this finding.
type Automation struct {
	Action     string
	Target     []string
	Exclude    []string
	Properties struct {
		DryRun bool `yaml:"dry_run"`
	}
}

// Finding represents this finding.
type Finding struct {
	enableBucketOnlyPolicy *pb.StorageScanner
}

// Name returns the rule name of the finding.
func (f *Finding) Name(b []byte) string {
	var finding pb.StorageScanner
	if err := json.Unmarshal(b, &finding); err != nil {
		return ""
	}
	return finding.GetFinding().GetCategory()
}

// New returns a new finding.
func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.enableBucketOnlyPolicy); err != nil {
		return nil, err
	}
	return &f, nil
}

// EnableBucketOnlyPolicy returns values for the enable bucket only policy automation.
func (f *Finding) EnableBucketOnlyPolicy() *enablebucketonlypolicy.Values {
	return &enablebucketonlypolicy.Values{
		ProjectID:  f.enableBucketOnlyPolicy.GetFinding().GetSourceProperties().GetProjectId(),
		BucketName: sha.BucketName(f.enableBucketOnlyPolicy.GetFinding().GetResourceName()),
	}
}
