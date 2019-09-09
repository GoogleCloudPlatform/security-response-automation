/*
Package firewall contains methods to interact with firewall settings.

Copyright 2019 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package firewall

import (
	"github.com/GoogleCloudPlatform/threat-automation/automation/clients"

	"fmt"

	cs "google.golang.org/api/compute/v1"
)

type client interface {
	clients.ComputeService
}

// Firewall struct
type Firewall struct {
	c client
}

// NewFirewall returns a new instance of firewall.
func NewFirewall(c client) *Firewall {
	return &Firewall{c: c}
}

// EnableFirewallRule sets the firewall rule to enabled.
func (f *Firewall) EnableFirewallRule(projectID string, name string) (*cs.Operation, error) {
	rb := &cs.Firewall{Disabled: false}
	resp, err := f.c.PatchFirewallRule(projectID, name, rb)
	if err != nil {
		return nil, fmt.Errorf("failed to enable firewall rule: %q", err)
	}
	return resp, nil
}

// DisableFirewallRule sets the firewall rule to disabled.
func (f *Firewall) DisableFirewallRule(projectID string, name string) (*cs.Operation, error) {
	rb := &cs.Firewall{Disabled: true}
	resp, err := f.c.PatchFirewallRule(projectID, name, rb)
	if err != nil {
		return nil, fmt.Errorf("failed to disable firewall rule: %q", err)
	}
	return resp, nil
}
