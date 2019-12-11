package removenonorgmembers

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
	"github.com/googlecloudplatform/security-response-automation/clients/stubs"
	"github.com/googlecloudplatform/security-response-automation/services"
	"golang.org/x/xerrors"
	crm "google.golang.org/api/cloudresourcemanager/v1"
)

func TestReadFinding(t *testing.T) {
	const (
		organizationFinding = `{
		"notificationConfigName": "organizations/1050000000008/notificationConfigs/noticonf-active-001-id",
		"finding": {
			"name": "organizations/1050000000008/sources/1986930501000008034/findings/29f4085b953299805367b2dd86e3c087",
		  	"parent": "organizations/1050000000008/sources/1986930501000008034",
		  	"resourceName": "//cloudresourcemanager.googleapis.com/organizations/1050000000008",
		  	"state": "ACTIVE",
		  	"category": "NON_ORG_IAM_MEMBER",
		  	"externalUri": "https://console.cloud.google.com/iam-admin/iam?organizationId=1050000000008",
		  	"sourceProperties": {
				"ReactivationCount": 0,
				"ExceptionInstructions": "Add the security mark \"allow_non_org_iam_member\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
				"SeverityLevel": "High",
				"Recommendation": "Go to https://console.cloud.google.com/iam-admin/iam?organizationId=1050000000008 and remove entries for users which are not in your organization (e.g. gmail.com addresses).",
				"ProjectId": "(none)",
				"AssetCreationTime": "2017-12-26T20:11:38.537Z",
				"ScannerName": "IAM_SCANNER",
				"ScanRunId": "2019-10-10T02:30:24.033-07:00",
				"Explanation": "A user outside of your organization has IAM permissions on a project or organization."
		  	},
		  	"securityMarks": {
				"name": "organizations/1050000000008/sources/1986930501000008034/findings/29f4085b953299805367b2dd86e3c087/securityMarks"
			},
		  	"eventTime": "2019-10-10T09:30:24.033Z",
		  	"createTime": "2019-09-13T22:51:00.516Z"
		}
	}`
		findingOtherCategory = `{
		"notificationConfigName": "organizations/1050000000008/notificationConfigs/noticonf-active-001-id",
		"finding": {
			"name": "organizations/1050000000008/sources/1986930501000008034/findings/29f4085b953299805367b2dd86e3c087",
		  	"parent": "organizations/1050000000008/sources/1986930501000008034",
		  	"resourceName": "//cloudresourcemanager.googleapis.com/organizations/1050000000008",
		  	"state": "ACTIVE",
		  	"category": "ANY_OTHER_SHA",
		  	"externalUri": "https://console.cloud.google.com/iam-admin/iam?organizationId=1050000000008",
		  	"sourceProperties": {
				"ReactivationCount": 0,
				"ExceptionInstructions": "Add the security mark \"allow_non_org_iam_member\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
				"SeverityLevel": "High",
				"Recommendation": "Go to https://console.cloud.google.com/iam-admin/iam?organizationId=1050000000008 and remove entries for users which are not in your organization (e.g. gmail.com addresses).",
				"ProjectId": "(none)",
				"AssetCreationTime": "2017-12-26T20:11:38.537Z",
				"ScannerName": "IAM_SCANNER",
				"ScanRunId": "2019-10-10T02:30:24.033-07:00",
				"Explanation": "A user outside of your organization has IAM permissions on a project or organization."
		  	},
		  	"securityMarks": {
				"name": "organizations/1050000000008/sources/1986930501000008034/findings/29f4085b953299805367b2dd86e3c087/securityMarks"
			},
		  	"eventTime": "2019-10-10T09:30:24.033Z",
		  	"createTime": "2019-09-13T22:51:00.516Z"
		}
	}`
		projectFinding = `{
		"notificationConfigName": "organizations/1050000000008/notificationConfigs/noticonf-active-001-id",
		"finding": {
			"name": "organizations/1050000000008/sources/1986930501000008034/findings/047db1bc23a4b1fb00cbaa79b468945a",
			"parent": "organizations/1050000000008/sources/1986930501000008034",
			"resourceName": "//cloudresourcemanager.googleapis.com/projects/72300000536",
			"state": "ACTIVE",
			"category": "NON_ORG_IAM_MEMBER",
			"externalUri": "https://console.cloud.google.com/iam-admin/iam?project=next19-demo",
			"sourceProperties": {
				"ReactivationCount": 0,
				"ExceptionInstructions": "Add the security mark \"allow_non_org_iam_member\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
				"SeverityLevel": "High",
				"Recommendation": "Go to https://console.cloud.google.com/iam-admin/iam?project=next19-demo and remove entries for users which are not in your organization (e.g. gmail.com addresses).",
				"ProjectId": "next19-demo",
				"AssetCreationTime": "2019-02-26T15:41:40.726Z",
				"ScannerName": "IAM_SCANNER",
				"ScanRunId": "2019-10-18T08:30:22.082-07:00",
				"Explanation": "A user outside of your organization has IAM permissions on a project or organization."
			},
			"securityMarks": {
				"name": "organizations/1050000000008/sources/1986930501000008034/findings/047db1bc23a4b1fb00cbaa79b468945a/securityMarks"
			},
			"eventTime": "2019-10-18T15:30:22.082Z",
			"createTime": "2019-10-18T15:31:58.487Z"
		}
	}`
	)
	for _, tt := range []struct {
		name, projectID string
		bytes           []byte
		expectedError   error
	}{
		{name: "project", projectID: "next19-demo", bytes: []byte(projectFinding), expectedError: nil},
		{name: "organizations not supported", projectID: "", bytes: []byte(organizationFinding), expectedError: services.ErrValueNotFound},
		{name: "wrong category", projectID: "", bytes: []byte(findingOtherCategory), expectedError: services.ErrUnsupportedFinding},
	} {
		t.Run(tt.name, func(t *testing.T) {
			values, err := ReadFinding(tt.bytes)
			if tt.expectedError == nil && err != nil {
				t.Errorf("%s failed: %q", tt.name, err)
			}
			if tt.expectedError != nil && err != nil && !xerrors.Is(err, tt.expectedError) {
				t.Errorf("%s failed: got:%q want:%q", tt.name, err, tt.expectedError)
			}
			if err == nil && values.ProjectID != tt.projectID {
				t.Errorf("%s failed got:%s want:%s", tt.name, values.ProjectID, tt.projectID)
			}
		})
	}
}

func TestErrors(t *testing.T) {
	tests := []struct {
		name            string
		policyInput     []*crm.Binding
		expectedBinding []*crm.Binding
		allowDomains    []string
		expectedFail    bool
	}{
		{
			name: "empty list should fail",
			policyInput: createBindings([]string{
				"user:ddgo@cloudorg.com",
			}),
			expectedBinding: createBindings([]string{
				"user:ddgo@cloudorg.com",
			}),
			allowDomains: []string{},
			expectedFail: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &crm.Policy{Bindings: tt.policyInput}
			entity, _ := setupNonOrgTest(policy, tt.allowDomains)
			values := &Values{ProjectID: "project-id"}
			err := Execute(context.Background(), values, &Services{
				Resource:      entity.Resource,
				Configuration: entity.Configuration,
				Logger:        entity.Logger,
			})
			if tt.expectedFail && err == nil {
				t.Errorf("%s failed: %q", tt.name, err)
			}
		})

	}
}

func TestRemoveNonOrgMembers(t *testing.T) {
	tests := []struct {
		name            string
		policyInput     []*crm.Binding
		expectedBinding []*crm.Binding
		allowDomains    []string
	}{
		{
			name: "only remove users not in the allowed domain",
			policyInput: createBindings([]string{
				"user:anyone@google.com",
				"user:bob@gmail.com",
				"user:ddgo@cloudorg.com",
				"user:mans@cloudorg.com",
				"serviceAccount:473000000749@cloudbuild.gserviceaccount.com",
				"user:tim@thegmail.com",
				"group:admins@example.com",
				"domain:google.com"}),
			expectedBinding: createBindings([]string{
				"user:ddgo@cloudorg.com",
				"user:mans@cloudorg.com",
				"serviceAccount:473000000749@cloudbuild.gserviceaccount.com",
				"group:admins@example.com",
				"domain:google.com"}),
			allowDomains: []string{
				"cloudorg.com",
			},
		},
		{
			name: "several allowed domains",
			policyInput: createBindings([]string{
				"user:bob@gmail.com",
				"user:ddgo@cloudorg.com",
				"user:mans@cloudorg.com",
				"serviceAccount:473000000749@cloudbuild.gserviceaccount.com",
				"user:tim@thegmail.com",
				"user:anyone@google.com",
				"group:admins@example.com",
				"domain:aol.com",
				"user:guy@evilgoogle.com",
				"user:guy@google.evil.com",
				"user:mls@cloudorgevil.com",
				"user:mls@cloudorg.com.ev",
				"user:buddy@prod.google.com",
			}),
			expectedBinding: createBindings([]string{
				"user:ddgo@cloudorg.com",
				"user:mans@cloudorg.com",
				"serviceAccount:473000000749@cloudbuild.gserviceaccount.com",
				"user:anyone@google.com",
				"group:admins@example.com",
				"domain:aol.com",
				"user:buddy@prod.google.com",
			}),
			allowDomains: []string{
				"cloudorg.com",
				"google.com",
				"prod.google.com",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &crm.Policy{Bindings: tt.policyInput}
			entity, crmStub := setupNonOrgTest(policy, tt.allowDomains)
			values := &Values{ProjectID: "project-id"}
			err := Execute(context.Background(), values, &Services{
				Resource:      entity.Resource,
				Configuration: entity.Configuration,
				Logger:        entity.Logger,
			})
			if err != nil {
				t.Fatalf("%s failed: %q", tt.name, err)
			}
			if diff := cmp.Diff(crmStub.SavedSetPolicy.Bindings, tt.expectedBinding); diff != "" {
				t.Errorf("%v failed, difference: %+v", tt.name, diff)
			}
		})

	}
}

func setupNonOrgTest(policy *crm.Policy, allowed []string) (*services.Global, *stubs.ResourceManagerStub) {
	crmStub := &stubs.ResourceManagerStub{}
	crmStub.GetPolicyResponse = policy
	crmStub.GetAncestryResponse = services.CreateAncestors([]string{"project/678", "folder/593987969559", "organization/1055058813388"})
	loggerStub := &stubs.LoggerStub{}
	log := services.NewLogger(loggerStub)
	config := services.Configuration{
		RemoveNonOrgMembers: &services.RemoveNonOrgMembers{
			Target:       []string{"organizations/1055058813388/folders/593987969559/*"},
			AllowDomains: allowed,
		},
	}
	return &services.Global{
		Resource:      services.NewResource(crmStub, &stubs.StorageStub{}),
		Configuration: &config,
		Logger:        log,
	}, crmStub
}

func createBindings(members []string) []*crm.Binding {
	return []*crm.Binding{
		{
			Role:    "roles/editor",
			Members: members,
		},
	}
}
