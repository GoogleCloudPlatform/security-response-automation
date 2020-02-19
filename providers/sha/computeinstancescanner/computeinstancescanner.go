package computeinstancescanner

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/removepublicip"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/sha"
)

// Finding represents this finding.
type Finding struct {
	computeInstanceScanner *pb.ComputeInstanceScanner
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
	if err := json.Unmarshal(b, &f.computeInstanceScanner); err != nil {
		return nil, err
	}
	if f.AlreadyRemediated() {
		return nil, fmt.Errorf("remediation ignored! Finding already processed and remediated. Security Mark: \"sra-remediated-event-time:  %s\"", f.sraRemediated())
	}
	return &f, nil
}

// RemovePublicIP returns values for the remove public IP policy automation.
func (f *Finding) RemovePublicIP() *removepublicip.Values {
	return &removepublicip.Values{
		ProjectID:    f.computeInstanceScanner.GetFinding().GetSourceProperties().GetProjectID(),
		InstanceZone: sha.Zone(f.computeInstanceScanner.GetFinding().GetResourceName()),
		InstanceID:   sha.Instance(f.computeInstanceScanner.GetFinding().GetResourceName()),
		Mark:         f.computeInstanceScanner.GetFinding().GetEventTime(),
		Name:         f.computeInstanceScanner.GetFinding().GetName(),
	}
}

// sraRemediated returns the mark sra-remediated-event-time.
func (f *Finding) sraRemediated() string {
	marks := f.computeInstanceScanner.GetFinding().GetSecurityMarks().GetMarks()
	if marks != nil {
		return marks["sra-remediated-event-time"]
	}
	return ""
}

// AlreadyRemediated returns if the finding was remediated before or not.
func (f *Finding) AlreadyRemediated() bool {
	return f.sraRemediated() == f.computeInstanceScanner.GetFinding().GetEventTime()
}
