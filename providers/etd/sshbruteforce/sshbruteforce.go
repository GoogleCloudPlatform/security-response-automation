package sshbruteforce

import (
	"encoding/json"

	pb "github.com/googlecloudplatform/security-response-automation/compiled/etd/protos"
)

// Finding represents this finding.
type Finding struct{}

// Name returns the rule name of the finding.
func (f *Finding) Name(b []byte) string {
	var finding pb.SshBruteForce
	if err := json.Unmarshal(b, &finding); err != nil {
		return ""
	}
	return finding.JsonPayload.GetDetectionCategory().GetRuleName()
}
