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
	"fmt"

	"github.com/googlecloudplatform/security-response-automation/services"
	"github.com/pkg/errors"
)

// Values contains the required and optional values needed for this function.
type Values struct {
	Action       string
	ProjectID    string
	FirewallID   string
	SourceRanges []string
	DryRun       bool
}

// Services contains the services needed for this function.
type Services struct {
	Firewall *services.Firewall
	Resource *services.Resource
	Logger   *services.Logger
}

// Execute remediates an open firewall.
func Execute(ctx context.Context, values *Values, services *Services) error {
	if values.DryRun {
		services.Logger.Info("dry_run on, would have remediated firewall %q in project %q with action %q", values.FirewallID, values.ProjectID, values.Action)
		return nil
	}
	switch action := values.Action; action {
	case "block_ssh":
		return blockSSH(ctx, services.Logger, services.Firewall, values)
	case "disable":
		return disable(ctx, services.Logger, services.Firewall, values)
	case "delete":
		return delete(ctx, services.Logger, services.Firewall, values)
	case "update_source_range":
		return updateRange(ctx, services.Logger, services.Firewall, values)
	default:
		return fmt.Errorf("unknown open firewall remediation action: %q", action)
	}
}

func blockSSH(ctx context.Context, logr *services.Logger, fw *services.Firewall, values *Values) error {
	if err := fw.BlockSSH(ctx, values.ProjectID, values.SourceRanges); err != nil {
		return errors.Wrapf(err, "failed to block ssh on %q from %q", values.ProjectID, values.SourceRanges)
	}
	logr.Info("blocked ssh on %q from %q", values.ProjectID, values.SourceRanges)
	return nil
}

func disable(ctx context.Context, logr *services.Logger, fw *services.Firewall, values *Values) error {
	r, err := fw.FirewallRule(ctx, values.ProjectID, values.FirewallID)
	if err != nil {
		return err
	}
	op, err := fw.DisableFirewallRule(ctx, values.ProjectID, values.FirewallID, r.Name)
	if err != nil {
		return err
	}
	if errs := fw.WaitGlobal(values.ProjectID, op); len(errs) > 0 {
		return errs[0]
	}
	logr.Info("disabled firewall %q in project %q.", r.Name, values.ProjectID)
	return nil
}

func delete(ctx context.Context, logr *services.Logger, fw *services.Firewall, values *Values) error {
	r, err := fw.FirewallRule(ctx, values.ProjectID, values.FirewallID)
	if err != nil {
		return err
	}
	op, err := fw.DeleteFirewallRule(ctx, values.ProjectID, values.FirewallID)
	if err != nil {
		return err
	}
	if errs := fw.WaitGlobal(values.ProjectID, op); len(errs) > 0 {
		return errs[0]
	}
	logr.Info("deleted firewall %q in project %q.", r.Name, values.ProjectID)
	return nil
}

func updateRange(ctx context.Context, logr *services.Logger, fw *services.Firewall, values *Values) error {
	r, err := fw.FirewallRule(ctx, values.ProjectID, values.FirewallID)
	if err != nil {
		return err
	}
	if err := fw.UpdateFirewallRuleSourceRange(ctx, values.ProjectID, values.FirewallID, r.Name, values.SourceRanges); err != nil {
		return err
	}
	logr.Info("updated source range firewall %q in project %q.", r.Name, values.ProjectID)
	return nil
}
