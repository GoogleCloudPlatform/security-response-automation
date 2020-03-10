package firewallscanner

import (
	"encoding/json"
	"strings"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/openfirewall"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/sha"
)

// Finding represents this finding.
type Finding struct {
	FirewallScanner *pb.FirewallScanner
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
	if err := json.Unmarshal(b, &f.FirewallScanner); err != nil {
		return nil, err
	}
	return &f, nil
}

// OpenFirewall returns values for the remediate automation.
func (f *Finding) OpenFirewall() *openfirewall.Values {
	return &openfirewall.Values{
		ProjectID:  f.FirewallScanner.GetFinding().GetSourceProperties().GetProjectId(),
		FirewallID: sha.FirewallID(f.FirewallScanner.GetFinding().GetResourceName()),
	}
}
