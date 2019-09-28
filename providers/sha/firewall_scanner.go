package sha

import (
	"encoding/json"

	"cloud.google.com/go/pubsub"
	"github.com/pkg/errors"
)

var (
	// ErrNotFirewall thrown when ShaFinding is not a FIREWALL_SCANNER
	ErrNotFirewall = errors.New("not a FIREWALL_SCANNER Finding")
	// ErrUnknownRule thrown when the rule is unknown
	ErrUnknownRule         = errors.New("Unknown firewall category")
	supportedFirewallRules = map[string]bool{"OPEN_SSH_PORT": true, "OPEN_RDP_PORT": true, "OPEN_FIREWALL": true}
)

type firewallSourceProperties struct {
	Finding struct {
		SourceProperties struct {
			Allowed           string `json:"Allowed"`
			AllowedIPRange    string `json:"AllowedIpRange"`
			ActivationTrigger string `json:"ActivationTrigger"`
			SourceRange       string `json:"SourceRange"`
		}
	}
}

// FirewallScanner a Security Health Analytics finding
type FirewallScanner struct {
	sf *Finding
	fs firewallSourceProperties
}

// NewFirewallScanner creates a new FirewallScanner
func NewFirewallScanner(ps *pubsub.Message) (*FirewallScanner, error) {
	var f FirewallScanner
	b := NewFinding()

	if err := b.ReadFinding(ps); err != nil {
		return nil, errors.New(err.Error())
	}

	if err := json.Unmarshal(ps.Data, &f.fs); err != nil {
		return nil, errors.New(err.Error())
	}

	f.sf = b

	if f.sf.sp.Finding.SourceProperties.ScannerName != firewallScanner {
		return nil, errors.New(ErrNotFirewall.Error())
	}

	if !supportedFirewallRules[f.sf.a.Finding.Category] {
		return nil, errors.New(ErrUnknownRule.Error())
	}

	return &f, nil
}

// ProjectID returns the Security Health Analytics finding ProjectID
func (f *FirewallScanner) ProjectID() string {
	return f.sf.sp.Finding.SourceProperties.ProjectID
}

// ResourceName returns the finding ResourceName
func (f *FirewallScanner) ResourceName() string {
	return f.sf.a.Finding.ResourceName
}

// ScannerName returns the Security Health Analytics finding ScannerName
func (f *FirewallScanner) ScannerName() string {
	return f.sf.sp.Finding.SourceProperties.ScannerName
}

// Category returns the finding Category
func (f *FirewallScanner) Category() string {
	return f.sf.a.Finding.Category
}
