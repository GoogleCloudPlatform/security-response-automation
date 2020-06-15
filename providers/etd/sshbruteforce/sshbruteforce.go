package sshbruteforce

import (
	"encoding/json"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/openfirewall"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/etd/protos"
)

// Finding represents this finding.
type Finding struct {
	UseCSCC          bool
	sshBruteForce    *pb.SshBruteForce
	sshBruteForceSCC *pb.SshBruteForceSCC
}

// Name returns the rule name of the finding.
func (f *Finding) Name(b []byte) string {
	ff, err := New(b)
	if err != nil {
		return ""
	}
	name := ""
	if ff.UseCSCC {
		name = ff.sshBruteForceSCC.GetFinding().GetSourceProperties().GetDetectionCategory().GetRuleName()
	} else {
		name = ff.sshBruteForce.GetJsonPayload().GetDetectionCategory().GetRuleName()
	}
	if name != "ssh_brute_force" {
		return ""
	}
	return name
}

// New returns a new finding.
func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.sshBruteForce); err != nil {
		return nil, err
	}
	if f.sshBruteForce.GetJsonPayload().GetDetectionCategory().GetRuleName() != "" {
		return &f, nil
	}
	if err := json.Unmarshal(b, &f.sshBruteForceSCC); err != nil {
		return nil, err
	}
	f.UseCSCC = true
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

func sourceIPRangesSCC(finding *pb.SshBruteForceSCC) []string {
	ranges := []string{}
	attempts := finding.GetFinding().GetSourceProperties().GetProperties().GetLoginAttempts()
	for _, attempt := range attempts {
		ranges = append(ranges, attempt.GetSourceIp()+"/32")
	}
	return ranges
}

// OpenFirewall returns values for the Block SSH automation.
func (f *Finding) OpenFirewall() *openfirewall.Values {
	if f.UseCSCC {
		return &openfirewall.Values{
			ProjectID:    f.sshBruteForceSCC.GetFinding().GetSourceProperties().GetProperties().GetProjectId(),
			SourceRanges: sourceIPRangesSCC(f.sshBruteForceSCC),
		}
	}
	return &openfirewall.Values{
		ProjectID:    f.sshBruteForce.GetJsonPayload().GetProperties().GetProjectId(),
		SourceRanges: sourceIPRanges(f.sshBruteForce),
	}
}
