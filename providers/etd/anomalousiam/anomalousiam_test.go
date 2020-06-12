package anomalousiam

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/xerrors"
)

func TestReadFinding(t *testing.T) {
	const (
		sccAnomalousIAM = `{
			"notificationConfigName": "organizations/0000000000000/notificationConfigs/noticonf-active-001-id",
			"finding": {
				"name": "organizations/0000000000000/sources/0000000000000000000/findings/6a30ce604c11417995b1fa260753f3b5",
				"parent": "organizations/0000000000000/sources/0000000000000000000",
				"resourceName": "//cloudresourcemanager.googleapis.com/projects/000000000000",
				"state": "ACTIVE",
				"category": "Persistence: IAM Anomalous Grant",
				"externalUri": "https://console.cloud.google.com/home?project=onboarding-project",
				"sourceProperties": {
					"detectionCategory": {
						"ruleName": "iam_anomalous_grant"
					},
					"evidence": [{"sourceLogId": {"projectId": "onboarding-project"}}],
					"properties": {
						"sensitiveRoleGrant": {
							"members": ["user:john.doe@example.com", "user:jane.doe@example.com"]
						}
					}
				},
				"securityMarks": {},
				"eventTime": "2019-11-22T18:34:36.153Z",
				"createTime": "2019-11-22T18:34:36.688Z"
			}
		}`
		etdAnomalousIAM = `{
			"jsonPayload": {
				"properties": {
					"sensitiveRoleGrant": {
						"members": ["user:john.doe@example.com", "user:jane.doe@example.com"]
					}
				},
				"evidence": [{"sourceLogId": {"projectId": "onboarding-project"}}],
				"detectionCategory": {
					"ruleName": "iam_anomalous_grant"
				}
			},
			"logName": "projects/test-project/logs/threatdetection.googleapis.com` + "%%2F" + `detection"
		}`
	)
	for _, tt := range []struct {
		name, projectID string
		externalMembers []string
		bytes           []byte
		expectedError   error
		ruleName        string
	}{
		{name: "read etd", externalMembers: []string{"user:john.doe@example.com", "user:jane.doe@example.com"}, projectID: "onboarding-project", bytes: []byte(etdAnomalousIAM), expectedError: nil, ruleName: "iam_anomalous_grant"},
		{name: "read SCC", externalMembers: []string{"user:john.doe@example.com", "user:jane.doe@example.com"}, projectID: "onboarding-project", bytes: []byte(sccAnomalousIAM), expectedError: nil, ruleName: "iam_anomalous_grant"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := New(tt.bytes)
			if tt.expectedError == nil && err != nil {
				t.Fatalf("%s failed: %q", tt.name, err)
			}
			if tt.expectedError != nil && err != nil && !xerrors.Is(err, tt.expectedError) {
				t.Errorf("%s failed: got:%q want:%q", tt.name, err, tt.expectedError)
			}
			if name := r.Name(tt.bytes); name != tt.ruleName {
				t.Errorf("%q got:%q want:%q", tt.name, name, tt.ruleName)
			}
			if err == nil && r != nil {
				values := r.IAMRevoke()
				if diff := cmp.Diff(values.ExternalMembers, tt.externalMembers); diff != "" {
					t.Errorf("%s failed: diff:%s", tt.name, diff)
				}
				if values.ProjectID != tt.projectID {
					t.Errorf("%s failed: got:%q want:%q", tt.name, values.ProjectID, tt.projectID)
				}
			}
		})
	}
}
