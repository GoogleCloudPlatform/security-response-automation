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
	firewallScanner *pb.FirewallScanner
}

// RuleName returns the rule name of the finding.
func (f *Finding) RuleName() string {
	if f.firewallScanner.GetFinding().GetSourceProperties().GetScannerName() != "FIREWALL_SCANNER" {
		return ""
	}
	return strings.ToLower(f.firewallScanner.GetFinding().GetCategory())
}

// New returns a new finding.
func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.firewallScanner); err != nil {
		return nil, err
	}
	return &f, nil
}

// OpenFirewall returns values for the remediate automation.
func (f *Finding) OpenFirewall() *openfirewall.Values {
	return &openfirewall.Values{
		ProjectID:  f.firewallScanner.GetFinding().GetSourceProperties().GetProjectId(),
		FirewallID: sha.FirewallID(f.firewallScanner.GetFinding().GetResourceName()),
		Hash:       f.firewallScanner.GetFinding().GetSecurityMarks().GetMarks().GetSraRemediated(),
		Name:       f.firewallScanner.GetFinding().GetName(),
	}
}

// StringToBeHashed returns the string that will be used to generate the mark hash finding.
func (f *Finding) StringToBeHashed() string {
	return f.firewallScanner.GetFinding().GetEventTime() + f.firewallScanner.GetFinding().GetName()
}

// SraRemediated returns the sraRemediate mark of the finding.
func (f *Finding) SraRemediated() string {
	return f.firewallScanner.GetFinding().GetSecurityMarks().GetMarks().GetSraRemediated()
}

// Deserialize deserializes the finding in object.
func (f *Finding) Deserialize(b []byte) error {
	if err := json.Unmarshal(b, &f.firewallScanner); err != nil {
		return err
	}
	return nil
}
