package anomalousiam

import (
	"encoding/json"

	pb "github.com/googlecloudplatform/security-response-automation/compiled/etd/protos"
	"github.com/googlecloudplatform/security-response-automation/services"
	"github.com/pkg/errors"
)

// Fields contains the fields from the finding.
type Fields struct {
	ProjectID       string
	ExternalMembers []string
}

type Finding struct{}

func (f *Finding) Name(b []byte) string {
	var finding pb.BadIP
	if err := json.Unmarshal(b, &finding); err != nil {
		return ""
	}
	return finding.JsonPayload.GetDetectionCategory().GetRuleName()
}

// Populate will attempt to deserialize all supported findings for this function.
func Populate(b []byte) (*Fields, error) {
	var finding pb.AnomalousIAMGrant
	v := &Fields{}
	if err := json.Unmarshal(b, &finding); err != nil {
		return nil, errors.Wrap(services.ErrUnmarshal, err.Error())
	}
	switch finding.GetJsonPayload().GetDetectionCategory().GetSubRuleName() {
	case "external_member_added_to_policy":
		v.ProjectID = finding.GetJsonPayload().GetProperties().GetProjectId()
		v.ExternalMembers = finding.GetJsonPayload().GetProperties().GetExternalMembers()
	default:
		return nil, services.ErrUnsupportedFinding
	}
	if v.ProjectID == "" || len(v.ExternalMembers) == 0 {
		return nil, services.ErrValueNotFound
	}
	return v, nil
}
