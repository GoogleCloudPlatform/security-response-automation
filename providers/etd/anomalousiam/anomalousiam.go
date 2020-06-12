// Package anomalousiam represents the anomalous IAM grant finding.
package anomalousiam

import (
	"encoding/json"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/iam/revoke"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/etd/protos"
)

// Name verifies and returns the rule name of the finding.
func (f *Finding) Name(b []byte) string {
	ff, err := New(b)
	if err != nil {
		return ""
	}
	name := ""
	if ff.UseCSCC {
		name = ff.anomalousIAMSCC.GetFinding().GetSourceProperties().GetDetectionCategory().GetRuleName()
	} else {
		name = ff.anomalousIAM.GetJsonPayload().GetDetectionCategory().GetRuleName()
	}
	if name != "iam_anomalous_grant" {
		return ""
	}
	return name
}

// New returns a new finding.
func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.anomalousIAM); err != nil {
		return nil, err
	}
	if f.anomalousIAM.GetJsonPayload().GetDetectionCategory().GetRuleName() != "" {
		return &f, nil
	}
	if err := json.Unmarshal(b, &f.anomalousIAMSCC); err != nil {
		return nil, err
	}
	f.UseCSCC = true
	return &f, nil
}

// Finding represents this finding.
type Finding struct {
	UseCSCC         bool
	anomalousIAM    *pb.AnomalousIAMGrant
	anomalousIAMSCC *pb.AnomalousIAMGrantSCC
}

// IAMRevoke returns values for the IAM revoke automation.
func (f *Finding) IAMRevoke() *revoke.Values {
	if f.UseCSCC {
		return &revoke.Values{
			ProjectID:       f.anomalousIAMSCC.GetFinding().GetSourceProperties().GetEvidence()[0].GetSourceLogId().GetProjectId(),
			ExternalMembers: f.anomalousIAMSCC.GetFinding().GetSourceProperties().GetProperties().GetSensitiveRoleGrant().GetMembers(),
		}
	}
	return &revoke.Values{
		ProjectID:       f.anomalousIAM.GetJsonPayload().GetEvidence()[0].GetSourceLogId().GetProjectId(),
		ExternalMembers: f.anomalousIAM.GetJsonPayload().GetProperties().GetSensitiveRoleGrant().GetMembers(),
	}
}
