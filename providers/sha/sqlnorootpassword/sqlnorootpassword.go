package sqlnorootpassword

import (
	"encoding/json"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/cloud-sql/updatepassword"
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
	sqlnorootpassword *pb.SqlScanner
}

// Name returns the rule name of the finding.
func (f *Finding) Name(b []byte) string {
	var finding pb.SqlScanner
	if err := json.Unmarshal(b, &finding); err != nil {
		return ""
	}
	return finding.GetFinding().GetCategory()
}

// New returns a new finding.
func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.sqlnorootpassword); err != nil {
		return nil, err
	}
	return &f, nil
}

// UpdatePassword returns values for the update password automation.
func (f *Finding) UpdatePassword() *updatepassword.Values {
	return &updatepassword.Values{
		ProjectID:    f.sqlnorootpassword.GetFinding().GetSourceProperties().GetProjectID(),
		InstanceName: sha.Instance(f.sqlnorootpassword.GetFinding().GetResourceName()),
	}
}
