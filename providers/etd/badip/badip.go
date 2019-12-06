package badip

import (
	"encoding/json"

	pb "github.com/googlecloudplatform/security-response-automation/compiled/etd/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/etd"
	"github.com/googlecloudplatform/security-response-automation/services"
	"github.com/pkg/errors"
)

// Fields contains the fields from the finding.
type Fields struct {
	ProjectID, RuleName, Instance, Zone string
}

type Finding struct{}

func (f *Finding) RuleName(b []byte) string {
	var finding pb.BadIP
	if err := json.Unmarshal(b, &finding); err != nil {
		return ""
	}
	return finding.JsonPayload.GetDetectionCategory().GetRuleName()
}

func Populate(b []byte) (*Fields, error) {
	var finding pb.BadIP
	fields := &Fields{}
	if err := json.Unmarshal(b, &finding); err != nil {
		return nil, errors.Wrap(services.ErrUnmarshal, err.Error())
	}
	switch finding.GetJsonPayload().GetDetectionCategory().GetRuleName() {
	case "bad_ip":
		fields.ProjectID = finding.GetJsonPayload().GetProperties().GetProjectId()
		fields.RuleName = finding.GetJsonPayload().GetDetectionCategory().GetRuleName()
		fields.Instance = etd.Instance(finding.GetJsonPayload().GetProperties().GetInstanceDetails())
		fields.Zone = etd.Zone(finding.GetJsonPayload().GetProperties().GetInstanceDetails())
	default:
		return nil, services.ErrUnsupportedFinding
	}
	if fields.RuleName == "" || fields.ProjectID == "" || fields.Instance == "" || fields.Zone == "" {
		return nil, services.ErrValueNotFound
	}
	return fields, nil
}
