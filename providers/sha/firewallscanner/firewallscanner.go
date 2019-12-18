package firewallscanner

import (
	"encoding/json"
	"strings"

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
		DryRun            bool     `yaml:"dry_run"`
		SourceRanges      []string `yaml:"source_ranges"`
		RemediationAction string   `yaml:"remediation_action"`
		Output            []string
		PagerDuty         struct {
			Enabled   bool   `yaml:"enabled"`
			APIKey    string `yaml:"api_key"`
			ServiceID string `yaml:"service_id"`
			From      string `yaml:"from"`
		} `yaml:"pagerduty"`
	}
}

// Finding represents this finding.
type Finding struct {
	firewallScanner *pb.FirewallScanner
}

// Name returns the rule name of the finding.
func (f *Finding) Name(b []byte) string {
	var finding pb.FirewallScanner
	if err := json.Unmarshal(b, &finding); err != nil {
		return ""
	}
	return strings.ToLower(finding.GetFinding().GetCategory())
}

// New returns a new finding.
func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.firewallScanner); err != nil {
		return nil, err
	}
	return &f, nil
}

// Remediate returns values for the Remediate  automation.
func (f *Finding) Remediate() *openfirewall.Values {
	return &openfirewall.Values{
		ProjectID:  f.firewallScanner.GetFinding().GetSourceProperties().GetProjectId(),
		FirewallID: sha.FirewallID(f.firewallScanner.GetFinding().GetResourceName()),
	}
}
