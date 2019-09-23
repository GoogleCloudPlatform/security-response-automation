package entities

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
	compute "google.golang.org/api/compute/v1"
)

// FirewallClient holds the minimum interface required by the firewall entity.
type FirewallClient interface {
	PatchFirewallRule(string, string, *compute.Firewall) (*compute.Operation, error)
}

// Firewall entity.
type Firewall struct {
	c FirewallClient
}

// NewFirewall returns a new firewall entity.
func NewFirewall(cs FirewallClient) *Firewall {
	return &Firewall{c: cs}
}

// EnableFirewallRule sets the firewall rule to enabled.
func (f *Firewall) EnableFirewallRule(projectID, name string) (*compute.Operation, error) {
	return f.c.PatchFirewallRule(projectID, name, &compute.Firewall{Disabled: false})
}

// DisableFirewallRule sets the firewall rule to disabled.
func (f *Firewall) DisableFirewallRule(projectID, name string) (*compute.Operation, error) {
	return f.c.PatchFirewallRule(projectID, name, &compute.Firewall{Disabled: true})
}
