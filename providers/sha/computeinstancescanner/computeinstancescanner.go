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
	computeInstanceScanner *pb.ComputeInstanceScanner
}

// Category returns the category of the finding.
func (f *Finding) Category(b []byte) string {
	if err := json.Unmarshal(b, &f.computeInstanceScanner); err != nil {
		return ""
	}
	if f.computeInstanceScanner.GetFinding().GetSourceProperties().GetScannerName() != "COMPUTE_INSTANCE_SCANNER" {
		return ""
	}
	return strings.ToLower(f.computeInstanceScanner.GetFinding().GetCategory())
}

// New returns a new finding.
func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.computeInstanceScanner); err != nil {
		return nil, err
	}
	return &f, nil
}

// RemovePublicIP returns values for the remove public IP policy automation.
func (f *Finding) RemovePublicIP() *removepublicip.Values {
	return &removepublicip.Values{
		ProjectID:    f.computeInstanceScanner.GetFinding().GetSourceProperties().GetProjectID(),
		InstanceZone: sha.Zone(f.computeInstanceScanner.GetFinding().GetResourceName()),
		InstanceID:   sha.Instance(f.computeInstanceScanner.GetFinding().GetResourceName()),
		Hash:         f.computeInstanceScanner.GetFinding().GetSecurityMarks().GetMarks().GetSraRemediated(),
		Name:         f.computeInstanceScanner.GetFinding().GetName(),
	}
}

// StringToBeHashed returns the string that will be used to generate the mark hash finding.
func (f *Finding) StringToBeHashed() string {
	return f.computeInstanceScanner.GetFinding().GetEventTime() + f.computeInstanceScanner.GetFinding().GetName()
}

// SraRemediated returns the sraRemediate mark of the finding.
func (f *Finding) SraRemediated() string {
	return f.computeInstanceScanner.GetFinding().GetSecurityMarks().GetMarks().GetSraRemediated()
}
