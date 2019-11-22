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

	etdPb "github.com/googlecloudplatform/security-response-automation/compiled/stackdriver/protos"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/scc/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/scc"
	"github.com/googlecloudplatform/security-response-automation/services"
	"github.com/pkg/errors"
)

// Values contains the required values needed for this function.
type Values struct {
	// ProjectId is a required field identifying which project ID to modify.
	ProjectID string
	// FirewallID is an optional field used with SHA findings only.
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
	var values Values

	switch err := readETDFinding(b, &values); err {
	case services.ErrUnmarshal:
		fallthrough
	case services.ErrValueNotFound:
		fallthrough
	case services.ErrUnsupportedFinding:
		return nil, err
	case services.ErrSkipFinding:
		// Incoming finding not from ETD, pass to next.
	case nil:
		return &values, nil
	}

	switch err := readSHAFinding(b, &values); err {
	case services.ErrUnmarshal:
		fallthrough
	case services.ErrValueNotFound:
		fallthrough
	case services.ErrUnsupportedFinding:
		return nil, err
	case services.ErrSkipFinding:
		// Incoming finding not from SHA, pass to next.
	case nil:
		return &values, nil
	}

	return nil, errors.New("failed to read finding")
}

func readETDFinding(b []byte, values *Values) error {
	var etdFinding etdPb.SshBruteForce
	if err := json.Unmarshal(b, &etdFinding); err != nil {
		return errors.Wrap(services.ErrUnmarshal, err.Error())
	}
	if etdFinding.GetJsonPayload() == nil {
		return services.ErrSkipFinding
	}
	switch etdFinding.GetJsonPayload().GetDetectionCategory().GetRuleName() {
	case "ssh_brute_force":
		values.ProjectID = etdFinding.GetJsonPayload().GetProperties().GetProjectId()
		values.SourceRanges = sourceIPRanges(&etdFinding)
	default:
		return services.ErrUnsupportedFinding
	}
	return nil
}

// sourceIPRanges will return a slice of IP ranges from an SSH brute force.
func sourceIPRanges(finding *etdPb.SshBruteForce) []string {
	ranges := []string{}
	attempts := finding.GetJsonPayload().GetProperties().GetLoginAttempts()
	for _, attempt := range attempts {
		ranges = append(ranges, attempt.GetSourceIp()+"/32")
	}
	return ranges
}

func readSHAFinding(b []byte, values *Values) error {
	var shaFinding pb.FirewallScanner
	if err := json.Unmarshal(b, &shaFinding); err != nil {
		return errors.Wrap(services.ErrUnmarshal, err.Error())
	}
	switch shaFinding.GetFinding().GetCategory() {
	case "OPEN_FIREWALL":
		fallthrough
	case "OPEN_SSH_PORT":
		fallthrough
	case "OPEN_RDP_PORT":
		if scc.IgnoreFinding(shaFinding.GetFinding()) {
			return services.ErrUnsupportedFinding
		}
		values.FirewallID = scc.FirewallID(shaFinding.GetFinding().GetResourceName())
		values.ProjectID = shaFinding.GetFinding().GetSourceProperties().GetProjectId()
	default:
		return services.ErrUnsupportedFinding
	}
	if values.FirewallID == "" || values.ProjectID == "" {
		return services.ErrValueNotFound
	}
	return nil
}

// Execute remediates an open firewall.
func Execute(ctx context.Context, values *Values, services *Services) error {
	resources := services.Configuration.DisableFirewall.Resources
	if services.Configuration.DisableFirewall.DryRun {
		services.Logger.Info("dry_run on, would have remediated firewall %q in project %q with action %q", values.FirewallID, values.ProjectID, services.Configuration.DisableFirewall.RemediationAction)
		return nil
	}
	var fn func() error
	switch action := services.Configuration.DisableFirewall.RemediationAction; action {
	case "BLOCK_SSH":
		fn = func() error {
			if err := services.Firewall.BlockSSH(ctx, values.ProjectID, values.SourceRanges); err != nil {
				return errors.Wrapf(err, "failed to block ssh on %q from %q", values.ProjectID, values.SourceRanges)
			}
			services.Logger.Info("blocked ssh on %q from %q", values.ProjectID, values.SourceRanges)
			return nil
		}
	case "DISABLE":
		fn = disable(ctx, services.Logger, services.Firewall, values.ProjectID, values.FirewallID)
	case "DELETE":
		fn = delete(ctx, services.Logger, services.Firewall, values.ProjectID, values.FirewallID)
	case "UPDATE_RANGE":
		fn = updateRange(ctx, services.Logger, services.Configuration.DisableFirewall.SourceRanges, services.Firewall, values.ProjectID, values.FirewallID)
	default:
		return fmt.Errorf("unknown open firewall remediation action: %q", action)
	}
	log.Printf("remediation action: %q", services.Configuration.DisableFirewall.RemediationAction)
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
		if err := fw.UpdateFirewallRuleSourceRange(ctx, projectID, firewallID, r.Name, newRanges); err != nil {
			return err
		}
		logr.Info("updated source range firewall %q in project %q.", r.Name, projectID)
		return nil
	}
}
