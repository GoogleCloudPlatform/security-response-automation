package computeinstancescanner

import (
	"encoding/json"
	"strings"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/removepublicip"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/sha"
)

// Finding represents this finding.
type Finding struct {
	ComputeInstanceScanner *pb.ComputeInstanceScanner
}

// Name returns the rule name of the finding.
func (f *Finding) Name(b []byte) string {
	var finding pb.ComputeInstanceScanner
	if err := json.Unmarshal(b, &finding); err != nil {
		return ""
	}
	if finding.GetFinding().GetSourceProperties().GetScannerName() != "COMPUTE_INSTANCE_SCANNER" {
		return ""
	}
	return strings.ToLower(finding.GetFinding().GetCategory())
}

// New returns a new finding.
func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.ComputeInstanceScanner); err != nil {
		return nil, err
	}
	return &f, nil
}

// RemovePublicIP returns values for the remove public IP policy automation.
func (f *Finding) RemovePublicIP() *removepublicip.Values {
	return &removepublicip.Values{
		ProjectID:    f.ComputeInstanceScanner.GetFinding().GetSourceProperties().GetProjectID(),
		InstanceZone: sha.Zone(f.ComputeInstanceScanner.GetFinding().GetResourceName()),
		InstanceID:   sha.Instance(f.ComputeInstanceScanner.GetFinding().GetResourceName()),
	}
}
