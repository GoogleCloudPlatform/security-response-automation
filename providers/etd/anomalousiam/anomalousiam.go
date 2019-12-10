// Package anomalousiam represents the anomalous IAM grant finding.
package anomalousiam

import (
	"encoding/json"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/iam/revoke"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/etd/protos"
)

// Automation defines the configuration for this finding.
type Automation struct {
	Action     string
	Target     []string
	Exclude    []string
	Properties struct {
		DryRun       bool     `yaml:"dry_run"`
		AllowDomains []string `yaml:"allow_domains"`
	}
}

// Name returns the rule name of the finding.
func (f *Finding) Name(b []byte) string {
	var finding pb.AnomalousIAMGrant
	if err := json.Unmarshal(b, &finding); err != nil {
		return ""
	}
	return finding.JsonPayload.GetDetectionCategory().GetRuleName()
}

// New returns a new finding.
func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.anomalousIAM); err != nil {
		return nil, err
	}
	return &f, nil
}

// Finding represents this finding.
type Finding struct {
	anomalousIAM *pb.AnomalousIAMGrant
}

// Fields contains the fields from the finding.
type Fields struct {
	anomalousIAM *pb.AnomalousIAMGrant
}

// IAMRevoke returns values for the IAM revoke automation.
func (f *Finding) IAMRevoke() *revoke.Values {
	return &revoke.Values{
		ProjectID:       f.anomalousIAM.GetJsonPayload().GetProperties().GetProjectId(),
		ExternalMembers: f.anomalousIAM.GetJsonPayload().GetProperties().GetExternalMembers(),
	}
}
