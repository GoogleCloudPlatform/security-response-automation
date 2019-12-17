package computeinstancescanner

import (
	"encoding/json"
	"strings"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/removepublicip"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/sha"
)

// Automation defines the configuration for this finding.
type Automation struct {
	Action     string
	Target     []string
	Exclude    []string
	Properties struct {
		DryRun bool `yaml:"dry_run"`
	}
}

// Finding represents this finding.
type Finding struct {
	computeinstancescanner *pb.ComputeInstanceScanner
}

// Name returns the rule name of the finding.
func (f *Finding) Name(b []byte) string {
	var finding pb.ComputeInstanceScanner
	if err := json.Unmarshal(b, &finding); err != nil {
		return ""
	}
	return strings.ToLower(finding.GetFinding().GetCategory())
}

// New returns a new finding.
func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.computeinstancescanner); err != nil {
		return nil, err
	}
	return &f, nil
}

// RemovePublicIP returns values for the remove public IP policy automation.
func (f *Finding) RemovePublicIP() *removepublicip.Values {
	return &removepublicip.Values{
		ProjectID:    f.computeinstancescanner.GetFinding().GetSourceProperties().GetProjectID(),
		InstanceZone: sha.Zone(f.computeinstancescanner.GetFinding().GetResourceName()),
		InstanceID:   sha.Instance(f.computeinstancescanner.GetFinding().GetResourceName()),
	}
}
