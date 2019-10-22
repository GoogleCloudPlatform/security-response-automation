package removenonorgmembers

import (
	"context"
	"testing"

	"github.com/googlecloudplatform/threat-automation/clients/stubs"
	"github.com/googlecloudplatform/threat-automation/entities"

	"cloud.google.com/go/pubsub"
	"github.com/google/go-cmp/cmp"
	crm "google.golang.org/api/cloudresourcemanager/v1"
)

var (
	findingRemoveNonOrgMember = pubsub.Message{Data: []byte(`{
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
	}`)}
)

func TestRemoveNonOrgMembers(t *testing.T) {
	tests := []struct {
		name            string
		pubSubInput     pubsub.Message
		policyInput     []*crm.Binding
		expectedMembers []string
	}{
		{
			name:        "Remove non-Org user member (user:)",
			pubSubInput: findingRemoveNonOrgMember,
			policyInput: createBindings([]string{"user:bob@gmail.com", "user:ddgo@cloudorg.com", "user:mans@cloudorg.com",
				"serviceAccount:473000000749@cloudbuild.gserviceaccount.com", "user:tim@thegmail.com",
				"group:admins@example.com", "domain:google.com"}),
			expectedMembers: []string{"user:ddgo@cloudorg.com", "user:mans@cloudorg.com",
				"serviceAccount:473000000749@cloudbuild.gserviceaccount.com",
				"group:admins@example.com", "domain:google.com"},
		},
		{
			name:        "None non-Org user member to remove (user:)",
			pubSubInput: findingRemoveNonOrgMember,
			policyInput: createBindings([]string{"user:ddgo@cloudorg.com", "user:mans@cloudorg.com",
				"serviceAccount:473000000749@cloudbuild.gserviceaccount.com",
				"group:admins@example.com", "domain:google.com"}),
			expectedMembers: []string{"user:ddgo@cloudorg.com", "user:mans@cloudorg.com",
				"serviceAccount:473000000749@cloudbuild.gserviceaccount.com",
				"group:admins@example.com", "domain:google.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crmStub := &stubs.ResourceManagerStub{}
			storageStub := &stubs.StorageStub{}
			crmStub.GetOrganizationResponse = &crm.Organization{DisplayName: "cloudorg.com", Name: "organizations/1050000000008"}
			crmStub.GetPolicyResponse = &crm.Policy{Bindings: tt.policyInput}
			res := entities.NewResource(crmStub, storageStub)
			required := &Required{
				OrganizationName: "organizations/1050000000008",
			}
			if err := Execute(context.Background(), required, &entities.Entity{Resource: res}); err != nil {
				t.Errorf("Could not run %s due %q", tt.name, err)
			}
			for _, b := range crmStub.SavedSetPolicy.Bindings {
				if diff := cmp.Diff(b.Members, tt.expectedMembers); diff != "" {
					t.Errorf("%v failed\n exp:%v\n got:%v", tt.name, tt.expectedMembers, b.Members)
				}
			}
		})

	}
}

func createBindings(members []string) []*crm.Binding {
	return []*crm.Binding{
		{
			Role:    "roles/editor",
			Members: members,
		},
	}
}
