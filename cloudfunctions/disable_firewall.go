package cloudfunctions

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
// l

import (
	"context"
	"log"

	"cloud.google.com/go/pubsub"
	"github.com/googlecloudplatform/threat-automation/entities"
	"github.com/googlecloudplatform/threat-automation/providers/sha"
	"github.com/pkg/errors"
)

var supportedFirewallRules = map[string]bool{"OPEN_SSH_PORT": true, "OPEN_RDP_PORT": true, "OPEN_FIREWALL": true}

// DisableFirewall disable a firewall rule found by SHA
func DisableFirewall(ctx context.Context, m pubsub.Message, ent *entities.Entity) error {

	finding, err := sha.NewFirewallScanner(&m)
	if err != nil {
		return errors.Wrap(err, "failed to read finding")
	}

	if !supportedFirewallRules[finding.Category()] {
		log.Printf("Unknown firewall scanner category: %s. Known categories are OPEN_SSH_PORT, OPEN_RDP_PORT and OPEN_FIREWALL. Skipping execution.", finding.Category())
		return nil
	}

	if err := ent.Resource.IfProjectInFolders(ctx, ent.Configuration.DisableFirewall.Resources.FolderIDs, finding.ProjectID(), disable(ctx, finding, ent.Logger, ent.Firewall)); err != nil {
		return err
	}

	if err := ent.Resource.IfProjectInProjects(ctx, ent.Configuration.DisableFirewall.Resources.ProjectIDs, finding.ProjectID(), disable(ctx, finding, ent.Logger, ent.Firewall)); err != nil {
		return err
	}

	return nil
}

func disable(ctx context.Context, finding *sha.FirewallScanner, logr *entities.Logger, fw *entities.Firewall) func() error {
	return func() error {
		r, err := fw.FirewallRule(ctx, finding.ProjectID(), finding.FirewallID())
		if err != nil {
			return errors.Wrap(err, "failed to get the firewall rule")
		}
		logr.Info("disabling firewall %q in project %q.", r.Name, finding.ProjectID())
		op, err := fw.DisableFirewallRule(ctx, finding.ProjectID(), finding.FirewallID(), r.Name)
		if err != nil {
			return errors.Wrap(err, "failed to disable firewall rule:")
		}
		if errs := fw.WaitGlobal(finding.ProjectID(), op); len(errs) > 0 {
			return errors.Wrap(errs[0], "failed waiting firewall rule operation: first error")
		}
		return nil
	}
}
