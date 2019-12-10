// Package badip represents the bad IP finding.
package badip

import (
	"encoding/json"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/createsnapshot"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/etd/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/etd"
)

// Automation defines the configuration for this finding.
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

// Name returns the rule name of the finding.
func (f *Finding) Name(b []byte) string {
	var finding pb.BadIP
	if err := json.Unmarshal(b, &finding); err != nil {
		return ""
	}
	return finding.JsonPayload.GetDetectionCategory().GetRuleName()
}

// New returns a new finding.
func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.badIP); err != nil {
		return nil, err
	}
	return &f, nil
}

// Finding represents this finding.
type Finding struct {
	badIP *pb.BadIP
}

// CreateSnapshot returns values for the create snapshot automation.
func (f *Finding) CreateSnapshot() *createsnapshot.Values {
	return &createsnapshot.Values{
		ProjectID: f.badIP.GetJsonPayload().GetProperties().GetProjectId(),
		RuleName:  f.badIP.GetJsonPayload().GetDetectionCategory().GetRuleName(),
		Instance:  etd.Instance(f.badIP.GetJsonPayload().GetProperties().GetInstanceDetails()),
		Zone:      etd.Zone(f.badIP.GetJsonPayload().GetProperties().GetInstanceDetails()),
	}
}
