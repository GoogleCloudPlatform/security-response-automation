package firewallscanner

import (
	"encoding/json"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/openfirewall"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/sha"
)

// Automation defines the configuration for this finding.
type Automation struct {
	Action     string
	Target     []string
	Exclude    []string
	Properties struct {
		DryRun          bool   `yaml:"dry_run"`
		SourceRanges    string `yaml:"source_ranges"`
		RemediateAction string `yaml:"remediate_action"`
	}
}

// Finding represents this finding.
type Finding struct {
	firewallscanner *pb.FirewallScanner
}

// Name returns the rule name of the finding.
func (f *Finding) Name(b []byte) string {
	var finding pb.FirewallScanner
	if err := json.Unmarshal(b, &finding); err != nil {
		return ""
	}
	return finding.GetFinding().GetCategory()
}

// New returns a new finding.
func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.firewallscanner); err != nil {
		return nil, err
	}
	return &f, nil
}

// Remediate returns values for the Remediate  automation.
func (f *Finding) Remediate() *openfirewall.Values {
	return &openfirewall.Values{
		ProjectID:  f.firewallscanner.GetFinding().GetSourceProperties().GetProjectId(),
		FirewallID: sha.FirewallID(f.firewallscanner.GetFinding().GetResourceName()),
	}
}
