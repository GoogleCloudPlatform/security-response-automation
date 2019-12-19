package sshbruteforce

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/xerrors"
)

func TestReadFinding(t *testing.T) {
	const (
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
	}{
		{name: "read etd", ranges: []string{"10.200.0.2/32", "10.200.0.3/32"}, projectID: "onboarding-project", firewallID: "", bytes: []byte(etdSSHBruteForceFinding), expectedError: nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := New(tt.bytes)
			if tt.expectedError == nil && err != nil {
				t.Fatalf("%s failed: %q", tt.name, err)
			}
			if tt.expectedError != nil && err != nil && !xerrors.Is(err, tt.expectedError) {
				t.Errorf("%s failed: got:%q want:%q", tt.name, err, tt.expectedError)
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
