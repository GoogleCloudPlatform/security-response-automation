package sha

// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import (
	"encoding/json"
	"regexp"

	"cloud.google.com/go/pubsub"
	"github.com/pkg/errors"
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
	*Finding
	fields firewallScanner
}

// NewFirewallScanner creates a new FirewallScanner
func NewFirewallScanner(ps *pubsub.Message) (*FirewallScanner, error) {
	f := FirewallScanner{}

	nf, err := NewFinding(ps)
	if err != nil {
		return nil, errors.New(err.Error())
	}

	f.Finding = nf

	if err := json.Unmarshal(ps.Data, &f.fields); err != nil {
		return nil, errors.New(err.Error())
	}

	if err := f.validate(); err != nil {
		return nil, err
	}

	return &f, nil
}

func (f *FirewallScanner) validate() error {

	if f.ScannerName() != "FIREWALL_SCANNER" {
		return errors.New("not a FIREWALL_SCANNER Finding")
	}

	if !supportedFirewallRules[f.Category()] {
		return errors.New("Unknown firewall category")
	}

	if f.ProjectID() == "" {
		return errors.New("does not have a project id")
	}

	return nil

}

// FirewallID return the numerical ID of the firewall. It is not the firewall name provided on creation
func (f *FirewallScanner) FirewallID() string {
	i := extractFirewallID.FindStringSubmatch(f.ResourceName())
	if len(i) != 2 {
		return ""
	}
	return i[1]
}
