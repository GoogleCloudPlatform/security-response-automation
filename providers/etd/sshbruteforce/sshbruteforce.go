package sshbruteforce

import (
	"encoding/json"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/openfirewall"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/etd/protos"
)

// Automation defines the configuration for this finding.
type Automation struct {
	Action     string
	Target     []string
	Exclude    []string
	Properties struct {
		DryRun    bool `yaml:"dry_run"`
		Output    []string
		PagerDuty struct {
			Enabled   bool   `yaml:"enabled"`
			APIKey    string `yaml:"api_key"`
			ServiceID string `yaml:"service_id"`
			From      string `yaml:"from"`
		} `yaml:"pagerduty"`
	}
}

// Finding represents this finding.
type Finding struct {
	sshbruteforce *pb.SshBruteForce
}

// Name returns the rule name of the finding.
func (f *Finding) Name(b []byte) string {
	var finding pb.SshBruteForce
	if err := json.Unmarshal(b, &finding); err != nil {
		return ""
	}
	return finding.GetJsonPayload().GetDetectionCategory().GetRuleName()
}

// New returns a new finding.
func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.sshbruteforce); err != nil {
		return nil, err
	}
	return &f, nil
}

// sourceIPRanges will return a slice of IP ranges from an SSH brute force.
func sourceIPRanges(finding *pb.SshBruteForce) []string {
	ranges := []string{}
	attempts := finding.GetJsonPayload().GetProperties().GetLoginAttempts()
	for _, attempt := range attempts {
		ranges = append(ranges, attempt.GetSourceIp()+"/32")
	}
	return ranges
}

// BlockSSH returns values for the Block SSH automation.
func (f *Finding) BlockSSH() *openfirewall.Values {
	return &openfirewall.Values{
		ProjectID:    f.sshbruteforce.GetJsonPayload().GetProperties().GetProjectId(),
		SourceRanges: sourceIPRanges(f.sshbruteforce),
	}
}
