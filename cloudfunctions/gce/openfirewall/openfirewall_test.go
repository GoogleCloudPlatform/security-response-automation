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
	"testing"

	"github.com/google/go-cmp/cmp"
	crm "google.golang.org/api/cloudresourcemanager/v1"
	compute "google.golang.org/api/compute/v1"

	"github.com/googlecloudplatform/security-response-automation/clients/stubs"
	"github.com/googlecloudplatform/security-response-automation/services"
)

func TestBlockSSH(t *testing.T) {
	for _, tt := range []struct {
		name         string
		ranges       []string
		bytes        []byte
		sourceRanges []string
		expected     *compute.Firewall
	}{
		{
			name:         "simple block",
			sourceRanges: []string{"10.0.0.1/32"},
			expected:     &compute.Firewall{SourceRanges: []string{"10.0.0.1/32"}},
		},
		{
			name:         "no source ranges",
			sourceRanges: nil,
			expected:     &compute.Firewall{},
		},
		{
			name:         "several source ranges",
			sourceRanges: []string{"10.0.0.1/32", "10.0.0.0/8", "192.168.0.0/24"},
			expected:     &compute.Firewall{SourceRanges: []string{"10.0.0.1/32", "10.0.0.0/8", "192.168.0.0/24"}},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			folderIDs := []string{"123"}
			svcs, computeStub, crmStub := openFirewallSetup(folderIDs, "BLOCK_SSH", []string{})
			computeStub.StubbedFirewall = &compute.Firewall{
				Id:           123,
				SourceRanges: []string{},
			}
			crmStub.GetAncestryResponse = services.CreateAncestors([]string{"folder/123"})
			svcs.Configuration.DisableFirewall.RemediationAction = "BLOCK_SSH"
			values := &Values{
				ProjectID:    "test-project",
				SourceRanges: tt.sourceRanges,
			}
			if err := Execute(ctx, values, &Services{
				Configuration: svcs.Configuration,
				Firewall:      svcs.Firewall,
				Resource:      svcs.Resource,
				Logger:        svcs.Logger,
			}); err != nil {
				t.Errorf("%s failed to disable firewall :%q", tt.name, err)
			}
			if diff := cmp.Diff(computeStub.SavedFirewallRule, tt.expected); diff != "" {
				t.Errorf("%s failed diff:%s", tt.name, diff)
			}
		})
	}
}
func TestOpenFirewall(t *testing.T) {
	ctx := context.Background()
	test := []struct {
		name              string
		firewallRule      *compute.Firewall
		expFirewallRule   *compute.Firewall
		folderIDs         []string
		ancestry          *crm.GetAncestryResponse
		remediationAction string
		sourceRange       []string
	}{
		{
			name:              "disable open firewall",
			firewallRule:      &compute.Firewall{Name: "default_allow_all", Disabled: false},
			expFirewallRule:   &compute.Firewall{Name: "default_allow_all", Disabled: true},
			folderIDs:         []string{"123"},
			ancestry:          services.CreateAncestors([]string{"folder/123"}),
			remediationAction: "DISABLE",
			sourceRange:       []string{"127.0.0.1/8"},
		},
		{
			name:              "update source range for open firewall",
			firewallRule:      &compute.Firewall{Name: "default_allow_all", Disabled: false, SourceRanges: []string{"0.0.0.0/0"}},
			expFirewallRule:   &compute.Firewall{Name: "default_allow_all", Disabled: false, SourceRanges: []string{"6.6.6.6/24"}},
			folderIDs:         []string{"123"},
			ancestry:          services.CreateAncestors([]string{"folder/123"}),
			remediationAction: "UPDATE_RANGE",
			sourceRange:       []string{"6.6.6.6/24"},
		},
		{
			name:              "delete open firewall",
			firewallRule:      &compute.Firewall{Name: "default_allow_all", Disabled: false},
			expFirewallRule:   nil,
			folderIDs:         []string{"123"},
			ancestry:          services.CreateAncestors([]string{"folder/123"}),
			remediationAction: "DELETE",
			sourceRange:       []string{"127.0.0.1/8"},
		},
		{
			name:              "no valid folder",
			firewallRule:      &compute.Firewall{Name: "default_allow_all", Disabled: false},
			expFirewallRule:   nil,
			folderIDs:         []string{"4242"},
			ancestry:          services.CreateAncestors([]string{"folder/123"}),
			remediationAction: "DISABLE",
			sourceRange:       []string{"127.0.0.1/8"},
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			svcs, computeStub, crmStub := openFirewallSetup(tt.folderIDs, tt.remediationAction, tt.sourceRange)
			tt.firewallRule.SourceRanges = []string{}
			computeStub.StubbedFirewall = tt.firewallRule
			crmStub.GetAncestryResponse = tt.ancestry
			values := &Values{
				ProjectID:  "test-project",
				FirewallID: "open-firewall-id",
			}
			if err := Execute(ctx, values, &Services{
				Configuration: svcs.Configuration,
				Firewall:      svcs.Firewall,
				Resource:      svcs.Resource,
				Logger:        svcs.Logger,
			}); err != nil {
				t.Errorf("%s failed to disable firewall :%q", tt.name, err)
			}
			if diff := cmp.Diff(computeStub.SavedFirewallRule, tt.expFirewallRule); diff != "" {
				t.Errorf("%v failed\n exp:%v\n got:%v", tt.name, tt.expFirewallRule, computeStub.SavedFirewallRule)
			}
		})
	}
}

func openFirewallSetup(folderIDs []string, remediationAction string, sourceRanges []string) (*services.Global, *stubs.ComputeStub, *stubs.ResourceManagerStub) {
	loggerStub := &stubs.LoggerStub{}
	log := services.NewLogger(loggerStub)
	computeStub := &stubs.ComputeStub{}
	storageStub := &stubs.StorageStub{}
	crmStub := &stubs.ResourceManagerStub{}
	res := services.NewResource(crmStub, storageStub)
	f := services.NewFirewall(computeStub)
	conf := &services.Configuration{
		DisableFirewall: &services.DisableFirewall{
			Resources: &services.Resources{
				FolderIDs: folderIDs,
			},
			RemediationAction: remediationAction,
			SourceRanges:      sourceRanges,
		},
	}
	return &services.Global{Logger: log, Firewall: f, Resource: res, Configuration: conf}, computeStub, crmStub
}
