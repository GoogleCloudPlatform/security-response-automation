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
	"fmt"
	"log"

	"github.com/pkg/errors"
	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
)

// sshBlockName is the firewall rule name created when blocking SSH.
const sshBlockName = "automatic-ssh-block"

// FirewallClient holds the minimum interface required by the firewall service.
type FirewallClient interface {
	InsertFirewallRule(context.Context, string, *compute.Firewall) (*compute.Operation, error)
	PatchFirewallRule(context.Context, string, string, *compute.Firewall) (*compute.Operation, error)
	FirewallRule(context.Context, string, string) (*compute.Firewall, error)
	DeleteFirewallRule(context.Context, string, string) (*compute.Operation, error)
	WaitGlobal(string, *compute.Operation) []error
}

// Firewall service.
type Firewall struct {
	client FirewallClient
}

// NewFirewall returns a new firewall service.
func NewFirewall(client FirewallClient) *Firewall {
	return &Firewall{client: client}
}

// BlockSSH will add a firewall rule that blocks SSH for the given project.
func (f *Firewall) BlockSSH(ctx context.Context, projectID string, sourceRanges []string) error {
	log.Printf("will attempt to block ssh for %q in %q", sourceRanges, projectID)
	fw, err := f.FirewallRule(ctx, projectID, sshBlockName)
	if err != nil {
		switch err.(*googleapi.Error).Code {
		case 404:
			log.Println("adding a new firewall rule to block ssh")
			return f.addFirewallRule(ctx, projectID, &compute.Firewall{
				Denied: []*compute.FirewallDenied{
					{
						IPProtocol: "tcp",
						Ports:      []string{"22"},
					},
				},
				Description:  "Block SSH TCP port 22 by Security Response Automation",
				Name:         sshBlockName,
				SourceRanges: sourceRanges,
			})
		default:
			return errors.Wrapf(err, "failed getting firewall rule: %q", sshBlockName)
		}
	}

	log.Printf("existing rule found, combine incoming source ranges %q with existing %q", sourceRanges, fw.SourceRanges)
	// Consider deduping. Currently this is done by the API.
	sourceRanges = append(sourceRanges, fw.SourceRanges...)
	ruleID := fmt.Sprintf("%d", fw.Id)
	if err := f.UpdateFirewallRuleSourceRange(ctx, projectID, ruleID, fw.Name, sourceRanges); err != nil {
		return errors.Wrapf(err, "failed to update source ranges for: %q %q %q", projectID, ruleID, fw.Name)
	}
	log.Printf("firewall rule %q updated in %q", fw.Name, projectID)
	return nil
}

// addFirewallRule will add a firewall rule.
func (f *Firewall) addFirewallRule(ctx context.Context, projectID string, fw *compute.Firewall) error {
	op, err := f.client.InsertFirewallRule(ctx, projectID, fw)
	if err != nil {
		return err
	}
	if errs := f.WaitGlobal(projectID, op); len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// EnableFirewallRule sets the firewall rule to enabled.
func (f *Firewall) EnableFirewallRule(ctx context.Context, projectID string, ruleID string, name string) (*compute.Operation, error) {
	return f.client.PatchFirewallRule(ctx, projectID, ruleID, &compute.Firewall{Name: name, Disabled: false})
}

// DisableFirewallRule sets the firewall rule to disabled.
func (f *Firewall) DisableFirewallRule(ctx context.Context, projectID string, ruleID string, name string) (*compute.Operation, error) {
	return f.client.PatchFirewallRule(ctx, projectID, ruleID, &compute.Firewall{Name: name, Disabled: true})
}

// UpdateFirewallRuleSourceRange updates the firewall source ranges
func (f *Firewall) UpdateFirewallRuleSourceRange(ctx context.Context, projectID string, ruleID string, name string, sourceRanges []string) error {
	op, err := f.client.PatchFirewallRule(ctx, projectID, ruleID, &compute.Firewall{Name: name, SourceRanges: sourceRanges})
	if err != nil {
		return err
	}
	if errs := f.WaitGlobal(projectID, op); len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// DeleteFirewallRule delete the firewall rule.
func (f *Firewall) DeleteFirewallRule(ctx context.Context, projectID string, ruleID string) (*compute.Operation, error) {
	return f.client.DeleteFirewallRule(ctx, projectID, ruleID)
}

// FirewallRule get a firewall rule
func (f *Firewall) FirewallRule(ctx context.Context, projectID string, ruleID string) (*compute.Firewall, error) {
	return f.client.FirewallRule(ctx, projectID, ruleID)
}

// WaitGlobal will wait for the global operation to complete.
func (f *Firewall) WaitGlobal(project string, op *compute.Operation) []error {
	return f.client.WaitGlobal(project, op)
}
