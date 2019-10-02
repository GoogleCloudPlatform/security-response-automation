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
	"fmt"

	"cloud.google.com/go/pubsub"
	"github.com/googlecloudplatform/threat-automation/entities"
	"github.com/googlecloudplatform/threat-automation/providers/sha"
)

const (
	scannerName = "FIREWALL_SCANNER"
)

// DisableFirewall disable a firewall rule found by SHA
func DisableFirewall(ctx context.Context, m pubsub.Message, f *entities.Firewall) error {

	finding, err := sha.NewFirewallScanner(&m)
	if err != nil {
		return fmt.Errorf("failed to create firewall scanner: %q", err)
	}

	projectID := finding.ProjectID()
	firewallID := finding.FirewallID()

	actualRule, err := f.GetFirewallRule(ctx, projectID, firewallID)
	if err != nil {
		return fmt.Errorf("failed to get the firewall rule: %q", err)
	}

	op, err := f.DisableFirewallRule(ctx, projectID, firewallID, actualRule.Name)
	if err != nil {
		return fmt.Errorf("failed to disable firewall rule: %q", err)
	}

	if errs := f.WaitGlobal(projectID, op); len(errs) > 0 {
		return fmt.Errorf("failed waiting")
	}
	return nil
}
