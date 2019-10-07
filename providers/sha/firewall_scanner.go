package sha

import (
	"encoding/json"
	"regexp"

	"cloud.google.com/go/pubsub"
	"github.com/pkg/errors"
)

const (
	firewallScannerName            = "FIREWALL_SCANNER"
	erroMsgNoProjectID             = "does not have a project id"
	erroMsgUnknownFirewallCategory = "Unknown firewall category"
	errorMsgNotFirewallScanner     = "not a FIREWALL_SCANNER Finding"
)

var (
	supportedFirewallRules = map[string]bool{"OPEN_SSH_PORT": true, "OPEN_RDP_PORT": true, "OPEN_FIREWALL": true}
	extractFirewallID      = regexp.MustCompile(`/global/firewalls/(.*)$`)
)

type firewallScanner struct {
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
	base   *CommonFinding
	fields firewallScanner
}

// NewFirewallScanner creates a new FirewallScanner
func NewFirewallScanner(ps *pubsub.Message) (*FirewallScanner, error) {
	var f FirewallScanner
	b := NewCommonFinding()

	if err := b.ReadFinding(ps); err != nil {
		return nil, errors.New(err.Error())
	}

	if err := json.Unmarshal(ps.Data, &f.fields); err != nil {
		return nil, errors.New(err.Error())
	}

	f.base = b

	if err := f.validate(); err != nil {
		return nil, err
	}

	return &f, nil
}

func (f *FirewallScanner) validate() error {

	if f.ScannerName() != firewallScannerName {
		return errors.New(errorMsgNotFirewallScanner)
	}

	if !supportedFirewallRules[f.Category()] {
		return errors.New(erroMsgUnknownFirewallCategory)
	}

	if f.ProjectID() == "" {
		return errors.New(erroMsgNoProjectID)
	}

	return nil

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
