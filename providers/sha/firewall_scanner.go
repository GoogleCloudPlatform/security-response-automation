package sha

import (
	"encoding/json"
	"regexp"

	"cloud.google.com/go/pubsub"
	"github.com/pkg/errors"
)

const (
	firewallScanner                = "FIREWALL_SCANNER"
	erroMsgNoProjectID             = "does not have a project id"
	erroMsgUnknownFirewallCategory = "Unknown firewall category"
	errorMsgNotFirewallScanner     = "not a FIREWALL_SCANNER Finding"
)

var (
	supportedFirewallRules = map[string]bool{"OPEN_SSH_PORT": true, "OPEN_RDP_PORT": true, "OPEN_FIREWALL": true}
	extractFirewallID      = regexp.MustCompile(`/global/firewalls/(.*)$`)
)

type firewallScannerSourceProperties struct {
	Finding struct {
		SourceProperties struct {
			Allowed           string
			AllowedIPRange    string
			ActivationTrigger string
			SourceRange       string
		}
	}
}

// FirewallScanner a Security Health Analytics finding
type FirewallScanner struct {
	base *CommonFinding
	fs   firewallScannerSourceProperties
}

// NewFirewallScanner creates a new FirewallScanner
func NewFirewallScanner(ps *pubsub.Message) (*FirewallScanner, error) {
	var f FirewallScanner
	b := NewCommonFinding()

	if err := b.ReadFinding(ps); err != nil {
		return nil, errors.New(err.Error())
	}

	if err := json.Unmarshal(ps.Data, &f.fs); err != nil {
		return nil, errors.New(err.Error())
	}

	f.base = b

	if f.ScannerName() != firewallScanner {
		return nil, errors.New(errorMsgNotFirewallScanner)
	}

	if !supportedFirewallRules[f.Category()] {
		return nil, errors.New(erroMsgUnknownFirewallCategory)
	}

	if f.ProjectID() == "" {
		return nil, errors.New(erroMsgNoProjectID)
	}

	return &f, nil
}

// ProjectID returns the Security Health Analytics finding ProjectID
func (f *FirewallScanner) ProjectID() string {
	return f.base.ProjectID()
}

// ResourceName returns the finding ResourceName
func (f *FirewallScanner) ResourceName() string {
	return f.base.ResourceName()
}

// ScannerName returns the Security Health Analytics finding ScannerName
func (f *FirewallScanner) ScannerName() string {
	return f.base.ScannerName()
}

// Category returns the finding Category
func (f *FirewallScanner) Category() string {
	return f.base.Category()
}

// FirewallID return the numerical ID of the firewall. It is not the firewall name provided on creation
func (f *FirewallScanner) FirewallID() string {
	i := extractFirewallID.FindStringSubmatch(f.ResourceName())
	if len(i) != 2 {
		return ""
	}
	return i[1]
}
