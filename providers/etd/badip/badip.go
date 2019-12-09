package badip

import (
	"encoding/json"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/createsnapshot"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/etd/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/etd"
)

// Automation defines which remediation function to call.
type Automation struct {
	Action     string
	Target     []string
	Exclude    []string
	Properties struct {
		DryRun                  bool   `yaml:"dry_run"`
		TargetSnapshotProjectID string `yaml:"target_snapshot_project_id"`
		TargetSnapshotZone      string `yaml:"target_snapshot_zone"`
		Output                  []string
		Turbinia                struct {
			ProjectID string
			Topic     string
			Zone      string
		}
	}
}

// Fields contains the fields from the finding.
type Fields struct {
	ProjectID, RuleName, Instance, Zone string
}

func (f *Finding) Name(b []byte) string {
	var finding pb.BadIP
	if err := json.Unmarshal(b, &finding); err != nil {
		return ""
	}
	return finding.JsonPayload.GetDetectionCategory().GetRuleName()
}

type Finding struct {
	badIP *pb.BadIP
}

func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.badIP); err != nil {
		return nil, err
	}
	return &f, nil
}

func (f *Finding) CreateSnapshot() *createsnapshot.Values {
	return &createsnapshot.Values{
		ProjectID: f.badIP.GetJsonPayload().GetProperties().GetProjectId(),
		RuleName:  f.badIP.GetJsonPayload().GetDetectionCategory().GetRuleName(),
		Instance:  etd.Instance(f.badIP.GetJsonPayload().GetProperties().GetInstanceDetails()),
		Zone:      etd.Zone(f.badIP.GetJsonPayload().GetProperties().GetInstanceDetails()),
	}
}
