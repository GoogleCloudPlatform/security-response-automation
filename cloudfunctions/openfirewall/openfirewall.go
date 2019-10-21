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
	"log"

	pb "github.com/googlecloudplatform/threat-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/threat-automation/entities"
	"github.com/googlecloudplatform/threat-automation/providers/sha"
	"github.com/pkg/errors"
)

// Required contains the required values needed for this function.
type Required struct {
	ProjectID, FirewallID string
}

// ReadFinding will attempt to deserialize all supported findings for this function.
func ReadFinding(b []byte) (*Required, error) {
	var finding pb.FirewallScanner
	r := &Required{}
	if err := json.Unmarshal(b, &finding); err != nil {
		return nil, errors.Wrap(entities.ErrUnmarshal, err.Error())
	}
	switch finding.GetFinding().GetCategory() {
	case "OPEN_FIREWALL":
		fallthrough
	case "OPEN_SSH_PORT":
		fallthrough
	case "OPEN_RDP_PORT":
		r.FirewallID = sha.FirewallID(finding.GetFinding().GetResourceName())
		r.ProjectID = finding.GetFinding().GetSourceProperties().GetProjectId()
	}
	if r.FirewallID == "" || r.ProjectID == "" {
		return nil, entities.ErrValueNotFound
	}
	return r, nil
}

// Execute remediates an open firewall.
func Execute(ctx context.Context, required *Required, ent *entities.Entity) error {
	folders := ent.Configuration.DisableFirewall.Resources.FolderIDs
	projects := ent.Configuration.DisableFirewall.Resources.ProjectIDs
	switch action := ent.Configuration.DisableFirewall.RemediationAction; action {
	case "DISABLE":
		d := disable(ctx, ent.Logger, ent.Firewall, required.ProjectID, required.FirewallID)
		if err := ent.Resource.IfProjectInFolders(ctx, folders, required.ProjectID, d); err != nil {
			return err
		}
		if err := ent.Resource.IfProjectInProjects(ctx, projects, required.ProjectID, d); err != nil {
			return err
		}
	case "DELETE":
		del := delete(ctx, ent.Logger, ent.Firewall, required.ProjectID, required.FirewallID)
		if err := ent.Resource.IfProjectInFolders(ctx, folders, required.ProjectID, del); err != nil {
			return err
		}
		if err := ent.Resource.IfProjectInProjects(ctx, projects, required.ProjectID, del); err != nil {
			return err
		}
	case "UPDATE_RANGE":
		up := updateRange(ctx, ent.Logger, ent.Configuration.DisableFirewall.SourceRanges, ent.Firewall, required.ProjectID, required.FirewallID)
		if err := ent.Resource.IfProjectInFolders(ctx, folders, required.ProjectID, up); err != nil {
			return err
		}
		if err := ent.Resource.IfProjectInProjects(ctx, projects, required.ProjectID, up); err != nil {
			return err
		}
	default:
		log.Printf("unknown open firewall remediation action %q.", action)
	}

	return nil
}

func disable(ctx context.Context, logr *entities.Logger, fw *entities.Firewall, projectID, firewallID string) func() error {
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

func delete(ctx context.Context, logr *entities.Logger, fw *entities.Firewall, projectID, firewallID string) func() error {
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

func updateRange(ctx context.Context, logr *entities.Logger, newRanges []string, fw *entities.Firewall, projectID, firewallID string) func() error {
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
