package firewallscanner

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/openfirewall"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/sha"
)

// Finding represents this finding.
type Finding struct {
	firewallScanner *pb.FirewallScanner
}

// Name returns the rule name of the finding.
func (f *Finding) Name(b []byte) string {
	var finding pb.FirewallScanner
	if err := json.Unmarshal(b, &finding); err != nil {
		return ""
	}
	if finding.GetFinding().GetSourceProperties().GetScannerName() != "FIREWALL_SCANNER" {
		return ""
	}
	return strings.ToLower(finding.GetFinding().GetCategory())
}

// New returns a new finding.
func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.firewallScanner); err != nil {
		return nil, err
	}
	if f.AlreadyRemediated() {
		return nil, fmt.Errorf("remediation ignored! Finding already processed and remediated. Security Mark: \"sra-remediated-event-time: %s\"", f.sraRemediated())
	}
	return &f, nil
}

// OpenFirewall returns values for the remediate automation.
func (f *Finding) OpenFirewall() *openfirewall.Values {
	return &openfirewall.Values{
		ProjectID:  f.firewallScanner.GetFinding().GetSourceProperties().GetProjectId(),
		FirewallID: sha.FirewallID(f.firewallScanner.GetFinding().GetResourceName()),
		Mark:       f.firewallScanner.GetFinding().GetEventTime(),
		Name:       f.firewallScanner.GetFinding().GetName(),
	}
}

// sraRemediated returns the mark sra-remediated-event-time.
func (f *Finding) sraRemediated() string {
	marks := f.firewallScanner.GetFinding().GetSecurityMarks().GetMarks()
	if marks != nil {
		return marks["sra-remediated-event-time"]
	}
	return ""
}

// AlreadyRemediated returns if the finding was remediated before or not.
func (f *Finding) AlreadyRemediated() bool {
	return f.sraRemediated() == f.firewallScanner.GetFinding().GetEventTime()
}
