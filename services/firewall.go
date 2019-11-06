package services

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
	"context"

	compute "google.golang.org/api/compute/v1"
)

// FirewallClient holds the minimum interface required by the firewall service.
type FirewallClient interface {
	PatchFirewallRule(context.Context, string, string, *compute.Firewall) (*compute.Operation, error)
	FirewallRule(context.Context, string, string) (*compute.Firewall, error)
	DeleteFirewallRule(context.Context, string, string) (*compute.Operation, error)
	WaitGlobal(string, *compute.Operation) []error
}

// Firewall service.
type Firewall struct {
	c FirewallClient
}

// NewFirewall returns a new firewall service.
func NewFirewall(cs FirewallClient) *Firewall {
	return &Firewall{c: cs}
}

// EnableFirewallRule sets the firewall rule to enabled.
func (f *Firewall) EnableFirewallRule(ctx context.Context, projectID string, ruleID string, name string) (*compute.Operation, error) {
	return f.c.PatchFirewallRule(ctx, projectID, ruleID, &compute.Firewall{Name: name, Disabled: false})
}

// DisableFirewallRule sets the firewall rule to disabled.
func (f *Firewall) DisableFirewallRule(ctx context.Context, projectID string, ruleID string, name string) (*compute.Operation, error) {
	return f.c.PatchFirewallRule(ctx, projectID, ruleID, &compute.Firewall{Name: name, Disabled: true})
}

// UpdateFirewallRuleSourceRange updates the firewall source ranges
func (f *Firewall) UpdateFirewallRuleSourceRange(ctx context.Context, projectID string, ruleID string, name string, sourceRanges []string) (*compute.Operation, error) {
	return f.c.PatchFirewallRule(ctx, projectID, ruleID, &compute.Firewall{Name: name, SourceRanges: sourceRanges})
}

// DeleteFirewallRule delete the firewall rule.
func (f *Firewall) DeleteFirewallRule(ctx context.Context, projectID string, ruleID string) (*compute.Operation, error) {
	return f.c.DeleteFirewallRule(ctx, projectID, ruleID)
}

// FirewallRule get a firewall rule
func (f *Firewall) FirewallRule(ctx context.Context, projectID string, ruleID string) (*compute.Firewall, error) {
	return f.c.FirewallRule(ctx, projectID, ruleID)
}

// WaitGlobal will wait for the global operation to complete.
func (f *Firewall) WaitGlobal(project string, op *compute.Operation) []error {
	return f.c.WaitGlobal(project, op)
}
