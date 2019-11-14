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
	"log"

	etdPb "github.com/googlecloudplatform/security-response-automation/compiled/etd/protos"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/sha"
	"github.com/googlecloudplatform/security-response-automation/services"
	"github.com/pkg/errors"
	compute "google.golang.org/api/compute/v1"
)

// Values contains the required values needed for this function.
type Values struct {
	// ProjectId is a required field identifying which project ID to modify.
	ProjectID string
	// FirewallID is an optional field used if a, b or c.
	FirewallID string
	// SourceRanges is a set of IPs of the orignating activity. This field is optional and used
	// only when blocking SSH.
	SourceRanges []string
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
	var shaFinding pb.FirewallScanner
	values := &Values{}
	if err := json.Unmarshal(b, &shaFinding); err != nil {
		return nil, errors.Wrap(services.ErrUnmarshal, err.Error())
	}
	log.Println("openfirewall read finding")
	if shaFinding.GetFinding().GetCategory() != "" {
		switch shaFinding.GetFinding().GetCategory() {
		case "OPEN_FIREWALL":
			fallthrough
		case "OPEN_SSH_PORT":
			fallthrough
		case "OPEN_RDP_PORT":
			if sha.IgnoreFinding(shaFinding.GetFinding()) {
				return nil, services.ErrUnsupportedFinding
			}
			values.FirewallID = sha.FirewallID(shaFinding.GetFinding().GetResourceName())
			values.ProjectID = shaFinding.GetFinding().GetSourceProperties().GetProjectId()
		default:
			return nil, services.ErrUnsupportedFinding
		}
		if values.FirewallID == "" || values.ProjectID == "" {
			return nil, services.ErrValueNotFound
		}
	} else {
		log.Println("openfirewall assume is an etd finding")
		var etdFinding etdPb.SshBruteForce
		if err := json.Unmarshal(b, &etdFinding); err != nil {
			return nil, errors.Wrap(services.ErrUnmarshal, err.Error())
		}
		log.Printf("finding: %q", etdFinding.GetJsonPayload().GetDetectionCategory().GetRuleName())
		switch etdFinding.GetJsonPayload().GetDetectionCategory().GetRuleName() {
		case "ssh_brute_force":
			values.ProjectID = etdFinding.GetJsonPayload().GetProperties().GetProjectId()
		default:
			return nil, services.ErrUnsupportedFinding
		}
		log.Printf("returning values: %+v\n", values)
	}
	log.Printf("returning values: %+v\n", values)
	return values, nil
}

// rename DisableFirwall to FirewallEnforcer.

// Execute remediates an open firewall.
func Execute(ctx context.Context, values *Values, services *Services) error {
	resources := services.Configuration.DisableFirewall.Resources
	var fn func() error
	switch action := services.Configuration.DisableFirewall.RemediationAction; action {
	case "BLOCK_SSH":
		fn = blockSSH(ctx, services.Configuration, services.Logger, services.Firewall, values.ProjectID)
	case "DISABLE":
		fn = disable(ctx, services.Logger, services.Firewall, values.ProjectID, values.FirewallID)
	case "DELETE":
		fn = delete(ctx, services.Logger, services.Firewall, values.ProjectID, values.FirewallID)
	case "UPDATE_RANGE":
		fn = updateRange(ctx, services.Logger, services.Configuration.DisableFirewall.SourceRanges, services.Firewall, values.ProjectID, values.FirewallID)
	default:
		return fmt.Errorf("unknown open firewall remediation action` %q", action)
	}
	log.Printf("remediation action: %q", services.Configuration.DisableFirewall.RemediationAction)
	return services.Resource.IfProjectWithinResources(ctx, resources, values.ProjectID, fn)
}

// blockSSH will automatically create a deny firewall rule for TCP port 22 against the offending source IPs.
// https://console.cloud.google.com/networking/firewalls/list?project=aerial-jigsaw-235219&organizationId=154584661726&firewallTablesize=50
// https://godoc.org/google.golang.org/api/compute/v1#Firewall
func blockSSH(ctx context.Context, conf *services.Configuration, logr *services.Logger, fw *services.Firewall, projectID string) func() error {
	return func() error {
		log.Println("blockSSH mode: %q", conf.DisableFirewall.Mode)
		if conf.DisableFirewall.Mode == "DRY_RUN" {
			logr.Info("dry_run on, would have blocked ssh in project %q", projectID)
			return nil
		}
		if err := fw.AddFirewallRule(ctx, projectID, &compute.Firewall{
			Denied: []*compute.FirewallDenied{
				{
					IPProtocol: "tcp",
					Ports:      []string{"22"},
				},
			},
			Description:  "Block SSH TCP port 22 by Security Response Automation",
			Name:         "automatic-ssh-block",
			SourceRanges: []string{},
		}); err != nil {
			return errors.Wrapf(err, "failed to add firweall rule to %q", projectID)
		}
		logr.Info("adding a firewall rule to block tcp port 22 in project %q.", projectID)
		return nil
	}
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
