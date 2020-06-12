package sshbruteforce

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/xerrors"
)

func TestReadFinding(t *testing.T) {
	const (
		sccSSHBruteForceFinding = `{
			"notificationConfigName": "organizations/0000000000000/notificationConfigs/noticonf-active-001-id",
			"finding": {
				"name": "organizations/0000000000000/sources/0000000000000000000/findings/6a30ce604c11417995b1fa260753f3b5",
				"parent": "organizations/0000000000000/sources/0000000000000000000",
				"resourceName": "//cloudresourcemanager.googleapis.com/projects/000000000000",
				"state": "ACTIVE",
				"category": "Brute_force: SSH Brute Force",
				"externalUri": "https://console.cloud.google.com/home?project=onboarding-project",
				"sourceProperties": {
					"detectionCategory": {
						"ruleName": "ssh_brute_force"
					},
					"properties": {
						"project_id": "onboarding-project",
						"loginAttempts": [{
							"authResult": "FAIL",
							"sourceIp": "10.200.0.2",
							"userName": "okokok",
							"vmName": "ssh-password-auth-debian-9"
							}, {
							"authResult": "SUCCESS",
							"sourceIp": "10.200.0.3",
							"userName": "okokok",
							"vmName": "ssh-password-auth-debian-9"
							}]
					}
				},
				"securityMarks": {},
				"eventTime": "2019-11-22T18:34:36.153Z",
				"createTime": "2019-11-22T18:34:36.688Z"
			}
		}`
		etdSSHBruteForceFinding = `{
		"jsonPayload": {
			"properties": {
				"project_id": "onboarding-project",
				"loginAttempts": [{
					"authResult": "FAIL",
					"sourceIp": "10.200.0.2",
					"userName": "okokok",
					"vmName": "ssh-password-auth-debian-9"
					}, {
					"authResult": "SUCCESS",
					"sourceIp": "10.200.0.3",
					"userName": "okokok",
					"vmName": "ssh-password-auth-debian-9"
				}]
			},
			"detectionCategory": {
			"ruleName": "ssh_brute_force"
			}
		},
		"logName": "projects/test-project/logs/threatdetection.googleapis.com` + "%%2F" + `detection"
	}`
	)
	for _, tt := range []struct {
		name, firewallID, projectID string
		ranges                      []string
		bytes                       []byte
		expectedError               error
		ruleName                    string
	}{
		{name: "read etd", ranges: []string{"10.200.0.2/32", "10.200.0.3/32"}, projectID: "onboarding-project", firewallID: "", bytes: []byte(etdSSHBruteForceFinding), expectedError: nil, ruleName: "ssh_brute_force"},
		{name: "read SCC", ranges: []string{"10.200.0.2/32", "10.200.0.3/32"}, projectID: "onboarding-project", firewallID: "", bytes: []byte(sccSSHBruteForceFinding), expectedError: nil, ruleName: "ssh_brute_force"},
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
				values := r.OpenFirewall()
				if diff := cmp.Diff(values.SourceRanges, tt.ranges); diff != "" {
					t.Errorf("%s failed: diff:%s", tt.name, diff)
				}
				if values.FirewallID != tt.firewallID {
					t.Errorf("%s failed: got:%q want:%q", tt.name, values.FirewallID, tt.firewallID)
				}
				if values.ProjectID != tt.projectID {
					t.Errorf("%s failed: got:%q want:%q", tt.name, values.ProjectID, tt.projectID)
				}
			}
		})
	}
}
