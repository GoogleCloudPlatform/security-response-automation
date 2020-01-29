package sshbruteforce

import (
	"encoding/json"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/openfirewall"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/etd/protos"
)

// Finding represents this finding.
type Finding struct {
	sshBruteForce *pb.SshBruteForce
}

// RuleName returns the rule name of the finding.
func (f *Finding) RuleName() string {
	if f.sshBruteForce.GetJsonPayload().GetDetectionCategory().GetRuleName() != "ssh_brute_force" {
		return ""
	}
	return f.sshBruteForce.GetJsonPayload().GetDetectionCategory().GetRuleName()
}

// New returns a new finding.
func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.sshBruteForce); err != nil {
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

// OpenFirewall returns values for the Block SSH automation.
func (f *Finding) OpenFirewall() *openfirewall.Values {
	return &openfirewall.Values{
		ProjectID:    f.sshBruteForce.GetJsonPayload().GetProperties().GetProjectId(),
		SourceRanges: sourceIPRanges(f.sshBruteForce),
	}
}

// Deserialize deserializes the finding in object.
func (f *Finding) Deserialize(b []byte) error {
	if err := json.Unmarshal(b, &f.sshBruteForce); err != nil {
		return err
	}
	return nil
}
