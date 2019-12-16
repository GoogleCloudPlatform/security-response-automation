package sslnotenforced

import (
	"encoding/json"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/cloud-sql/requiressl"
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
	sslnotenforced *pb.SqlScanner
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
	if err := json.Unmarshal(b, &f.sslnotenforced); err != nil {
		return nil, err
	}
	return &f, nil
}

// RequireSSL returns values for the require SSL automation.
func (f *Finding) RequireSSL() *requiressl.Values {
	return &requiressl.Values{
		ProjectID:    f.sslnotenforced.GetFinding().GetSourceProperties().GetProjectID(),
		InstanceName: sha.Instance(f.sslnotenforced.GetFinding().GetResourceName()),
	}
}
