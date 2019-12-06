package sshbruteforce

import (
	"encoding/json"

	pb "github.com/googlecloudplatform/security-response-automation/compiled/etd/protos"
)

type Finding struct{}

func (f *Finding) RuleName(b []byte) string {
	var finding pb.SshBruteForce
	if err := json.Unmarshal(b, &finding); err != nil {
		return ""
	}
	return finding.JsonPayload.GetDetectionCategory().GetRuleName()
}
