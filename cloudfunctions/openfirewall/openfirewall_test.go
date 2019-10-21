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
	"strings"
	"testing"

	"cloud.google.com/go/pubsub"
	"github.com/google/go-cmp/cmp"
	"github.com/googlecloudplatform/threat-automation/clients/stubs"
	"github.com/googlecloudplatform/threat-automation/entities"
	"golang.org/x/xerrors"
	crm "google.golang.org/api/cloudresourcemanager/v1"
	compute "google.golang.org/api/compute/v1"
)

func TestReadFinding(t *testing.T) {
	const (
		openFirewallFinding = `{
			"notificationConfigName": "organizations/1055058813388/notificationConfigs/noticonf-active-001-id",
			"finding": {
				"name": "organizations/1055058813388/sources/1986930501971458034/findings/cea981dd340112213827902b408b497e",
				"parent": "organizations/1055058813388/sources/1986930501971458034",
				"resourceName": "//compute.googleapis.com/projects/onboarding-project/global/firewalls/6190685430815455733",
				"state": "ACTIVE",
				"category": "OPEN_FIREWALL",
				"externalUri": "https://console.cloud.google.com/networking/firewalls/details/default-allow-http?project\u003donboarding-project",
				"sourceProperties": {
					"ReactivationCount": 0.0,
					"Allowed": "[{\"IPProtocol\":\"tcp\",\"ipProtocol\":\"tcp\",\"port\":[\"80\"],\"ports\":[\"80\"]}]",
					"ExceptionInstructions": "Add the security mark \"allow_open_firewall\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
					"SeverityLevel": "High",
					"Recommendation": "Restrict the firewall rules at: https://console.cloud.google.com/networking/firewalls/details/default-allow-http?project\u003donboarding-project",
					"AllowedIpRange": "All",
					"ActivationTrigger": "Allows all IP addresses",
					"ProjectId": "onboarding-project",
					"DeactivationReason": "The asset was deleted.",
					"SourceRange": "[\"0.0.0.0/0\"]",
					"AssetCreationTime": "2019-08-21t06:28:58.140-07:00",
					"ScannerName": "FIREWALL_SCANNER",
					"ScanRunId": "2019-09-17T07:10:21.961-07:00",
					"Explanation": "Firewall rules that allow connections from all IP addresses or on all ports may expose resources to attackers."
				},
				"securityMarks": {
					"name": "organizations/1055058813388/sources/1986930501971458034/findings/cea981dd340112213827902b408b497e/securityMarks",
					"marks": {
						"sccquery94c23b35ea0b4f8388268415a0dc6c1b": "true"
					}
				},
				"eventTime": "2019-09-19T16:58:39.276Z",
				"createTime": "2019-09-16T22:11:59.977Z"
			}
		}`

		wrongCategoryFinding = `{
			"notificationConfigName": "organizations/1055058813388/notificationConfigs/noticonf-active-001-id",
			"finding": {
				"name": "organizations/1055058813388/sources/1986930501971458034/findings/cea981dd340112213827902b408b497e",
				"parent": "organizations/1055058813388/sources/1986930501971458034",
				"resourceName": "//compute.googleapis.com/projects/onboarding-project/global/firewalls/6190685430815455733",
				"state": "ACTIVE",
				"category": "CLOSED_FIREWALL",
				"externalUri": "https://console.cloud.google.com/networking/firewalls/details/default-allow-http?project\u003donboarding-project",
				"sourceProperties": {
					"ReactivationCount": 0.0,
					"Allowed": "[{\"IPProtocol\":\"tcp\",\"ipProtocol\":\"tcp\",\"port\":[\"80\"],\"ports\":[\"80\"]}]",
					"ExceptionInstructions": "Add the security mark \"allow_open_firewall\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
					"SeverityLevel": "High",
					"Recommendation": "Restrict the firewall rules at: https://console.cloud.google.com/networking/firewalls/details/default-allow-http?project\u003donboarding-project",
					"AllowedIpRange": "All",
					"ActivationTrigger": "Allows all IP addresses",
					"ProjectId": "onboarding-project",
					"DeactivationReason": "The asset was deleted.",
					"SourceRange": "[\"0.0.0.0/0\"]",
					"AssetCreationTime": "2019-08-21t06:28:58.140-07:00",
					"ScannerName": "FIREWALL_SCANNER",
					"ScanRunId": "2019-09-17T07:10:21.961-07:00",
					"Explanation": "Firewall rules that allow connections from all IP addresses or on all ports may expose resources to attackers."
				},
				"securityMarks": {
					"name": "organizations/1055058813388/sources/1986930501971458034/findings/cea981dd340112213827902b408b497e/securityMarks",
					"marks": {
						"sccquery94c23b35ea0b4f8388268415a0dc6c1b": "true"
					}
				},
				"eventTime": "2019-09-19T16:58:39.276Z",
				"createTime": "2019-09-16T22:11:59.977Z"
			}
		}`
	)
	for _, tt := range []struct {
		name, firewallID, projectID string
		bytes                       []byte
		expectedError               error
	}{
		{name: "read", projectID: "onboarding-project", firewallID: "6190685430815455733", bytes: []byte(openFirewallFinding), expectedError: nil},
		{name: "wrong category", projectID: "", firewallID: "", bytes: []byte(wrongCategoryFinding), expectedError: entities.ErrValueNotFound},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := ReadFinding(tt.bytes)
			if tt.expectedError == nil && err != nil {
				t.Errorf("%s failed: %q", tt.name, err)
			}
			if tt.expectedError != nil && err != nil && !xerrors.Is(err, tt.expectedError) {
				t.Errorf("%s failed: got:%q want:%q", tt.name, err, tt.expectedError)
			}
			if err == nil && r.FirewallID != tt.firewallID {
				t.Errorf("%s failed: got:%q want:%q", tt.name, r.FirewallID, tt.firewallID)
			}
			if err == nil && r.ProjectID != tt.projectID {
				t.Errorf("%s failed: got:%q want:%q", tt.name, r.ProjectID, tt.projectID)
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
		finding           pubsub.Message
		remediationAction string
		sourceRange       []string
	}{
		{
			name:              "disable open firewall",
			firewallRule:      &compute.Firewall{Name: "default_allow_all", Disabled: false},
			expFirewallRule:   &compute.Firewall{Name: "default_allow_all", Disabled: true},
			folderIDs:         []string{"123"},
			ancestry:          createAncestors([]string{"folder/123"}),
			remediationAction: "DISABLE",
			sourceRange:       []string{"127.0.0.1/8"},
		},
		{
			name:              "update source range for open firewall",
			firewallRule:      &compute.Firewall{Name: "default_allow_all", Disabled: false, SourceRanges: []string{"0.0.0.0/0"}},
			expFirewallRule:   &compute.Firewall{Name: "default_allow_all", Disabled: false, SourceRanges: []string{"6.6.6.6/24"}},
			folderIDs:         []string{"123"},
			ancestry:          createAncestors([]string{"folder/123"}),
			remediationAction: "UPDATE_RANGE",
			sourceRange:       []string{"6.6.6.6/24"},
		},
		{
			name:              "delete open firewall",
			firewallRule:      &compute.Firewall{Name: "default_allow_all", Disabled: false},
			expFirewallRule:   nil,
			folderIDs:         []string{"123"},
			ancestry:          createAncestors([]string{"folder/123"}),
			remediationAction: "DELETE",
			sourceRange:       []string{"127.0.0.1/8"},
		},
		{
			name:              "no valid folder",
			firewallRule:      &compute.Firewall{Name: "default_allow_all", Disabled: false},
			expFirewallRule:   nil,
			folderIDs:         []string{"4242"},
			ancestry:          createAncestors([]string{"folder/123"}),
			remediationAction: "DISABLE",
			sourceRange:       []string{"127.0.0.1/8"},
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			ent, computeStub, crmStub := openFirewallSetup(tt.folderIDs, tt.remediationAction, tt.sourceRange)
			computeStub.StubbedFirewall = tt.firewallRule
			crmStub.GetAncestryResponse = tt.ancestry
			required := &Required{
				ProjectID:  "test-project",
				FirewallID: "open-firewall-id",
			}
			if err := Execute(ctx, required, ent); err != nil {
				t.Errorf("%s failed to disable firewall :%q", tt.name, err)
			}
			if diff := cmp.Diff(computeStub.SavedFirewallRule, tt.expFirewallRule); diff != "" {
				t.Errorf("%v failed\n exp:%v\n got:%v", tt.name, tt.expFirewallRule, computeStub.SavedFirewallRule)
			}
		})
	}
}

func openFirewallSetup(folderIDs []string, remediationAction string, sourceRanges []string) (*entities.Entity, *stubs.ComputeStub, *stubs.ResourceManagerStub) {
	loggerStub := &stubs.LoggerStub{}
	log := entities.NewLogger(loggerStub)
	computeStub := &stubs.ComputeStub{}
	storageStub := &stubs.StorageStub{}
	crmStub := &stubs.ResourceManagerStub{}
	res := entities.NewResource(crmStub, storageStub)
	f := entities.NewFirewall(computeStub)
	conf := &entities.Configuration{
		DisableFirewall: &entities.DisableFirewall{
			Resources: &entities.Resources{
				FolderIDs: folderIDs,
			},
			RemediationAction: remediationAction,
			SourceRanges:      sourceRanges,
		},
	}
	return &entities.Entity{Logger: log, Firewall: f, Resource: res, Configuration: conf}, computeStub, crmStub
}

func createAncestors(members []string) *crm.GetAncestryResponse {
	ancestors := []*crm.Ancestor{}
	// 'members' here looks like a resource string but it's really just an easy way to pass the
	// type and id in a single string easily. Note to leave off the "s" from "folders" which is added
	// downstream.
	for _, m := range members {
		mm := strings.Split(m, "/")
		ancestors = append(ancestors, &crm.Ancestor{
			ResourceId: &crm.ResourceId{
				Type: mm[0],
				Id:   mm[1],
			},
		})
	}
	return &crm.GetAncestryResponse{Ancestor: ancestors}
}
