package openfirewall

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
	"encoding/json"
	"fmt"

	pb "github.com/googlecloudplatform/security-response-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/sha"
	"github.com/googlecloudplatform/security-response-automation/services"
	"github.com/pkg/errors"
)

// Values contains the required values needed for this function.
type Values struct {
	ProjectID, FirewallID string
}

// Services contains the services needed for this function.
type Services struct {
	Configuration *services.Configuration
	Firewall      *services.Firewall
	Resource      *services.Resource
	Logger        *services.Logger
}

// ReadFinding will attempt to deserialize all supported findings for this function.
func ReadFinding(b []byte) (*Values, error) {
	var finding pb.FirewallScanner
	r := &Values{}
	if err := json.Unmarshal(b, &finding); err != nil {
		return nil, errors.Wrap(services.ErrUnmarshal, err.Error())
	}
	switch finding.GetFinding().GetCategory() {
	case "OPEN_FIREWALL":
		fallthrough
	case "OPEN_SSH_PORT":
		fallthrough
	case "OPEN_RDP_PORT":
		r.FirewallID = sha.FirewallID(finding.GetFinding().GetResourceName())
		r.ProjectID = finding.GetFinding().GetSourceProperties().GetProjectId()
	default:
		return nil, services.ErrUnsupportedFinding
	}
	if r.FirewallID == "" || r.ProjectID == "" {
		return nil, services.ErrValueNotFound
	}
	return r, nil
}

// Execute remediates an open firewall.
func Execute(ctx context.Context, values *Values, services *Services) error {
	resources := services.Configuration.DisableFirewall.Resources
	if services.Configuration.DisableFirewall.Mode == "DRY_RUN" {
		services.Logger.Info("dry_run on, would have remediated firewall %q in project  %q with action %q", values.FirewallID, values.ProjectID, services.Configuration.DisableFirewall.RemediationAction)
		return nil
	}
	var fn func() error
	switch action := services.Configuration.DisableFirewall.RemediationAction; action {
	case "DISABLE":
		fn = disable(ctx, services.Logger, services.Firewall, values.ProjectID, values.FirewallID)
	case "DELETE":
		fn = delete(ctx, services.Logger, services.Firewall, values.ProjectID, values.FirewallID)
	case "UPDATE_RANGE":
		fn = updateRange(ctx, services.Logger, services.Configuration.DisableFirewall.SourceRanges, services.Firewall, values.ProjectID, values.FirewallID)
	default:
		return fmt.Errorf("unknown open firewall remediation action` %q", action)
	}
	return services.Resource.IfProjectWithinResources(ctx, resources, values.ProjectID, fn)
}

func disable(ctx context.Context, logr *services.Logger, fw *services.Firewall, projectID, firewallID string) func() error {
	return func() error {
		r, err := fw.FirewallRule(ctx, projectID, firewallID)
		if err != nil {
			return err
		}
		op, err := fw.DisableFirewallRule(ctx, projectID, firewallID, r.Name)
		if err != nil {
			return err
		}
		if errs := fw.WaitGlobal(projectID, op); len(errs) > 0 {
			return errs[0]
		}
		logr.Info("disabled firewall %q in project %q.", r.Name, projectID)
		return nil
	}
}

func delete(ctx context.Context, logr *services.Logger, fw *services.Firewall, projectID, firewallID string) func() error {
	return func() error {
		r, err := fw.FirewallRule(ctx, projectID, firewallID)
		if err != nil {
			return err
		}
		op, err := fw.DeleteFirewallRule(ctx, projectID, firewallID)
		if err != nil {
			return err
		}
		if errs := fw.WaitGlobal(projectID, op); len(errs) > 0 {
			return errs[0]
		}
		logr.Info("deleted firewall %q in project %q.", r.Name, projectID)
		return nil
	}
}

func updateRange(ctx context.Context, logr *services.Logger, newRanges []string, fw *services.Firewall, projectID, firewallID string) func() error {
	return func() error {
		r, err := fw.FirewallRule(ctx, projectID, firewallID)
		if err != nil {
			return err
		}
		op, err := fw.UpdateFirewallRuleSourceRange(ctx, projectID, firewallID, r.Name, newRanges)
		if err != nil {
			return err
		}
		if errs := fw.WaitGlobal(projectID, op); len(errs) > 0 {
			return errs[0]
		}
		logr.Info("updated source range firewall %q in project %q.", r.Name, projectID)
		return nil
	}
}
