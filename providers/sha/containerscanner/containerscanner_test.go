package containerscanner

import (
	"testing"

	"golang.org/x/xerrors"
)

func TestReadFindingDisableDashboard(t *testing.T) {
	const (
		webUIFinding = `{
			"notificationConfigName": "organizations/154584661726/notificationConfigs/sampleConfigId",
			"finding": {
				"name": "organizations/119612413569/sources/7086426792249889955/findings/18db063343328e25a3997efaa0126274",
				"parent": "organizations/119612413569/sources/7086426792249889955",
				"resourceName": "//container.googleapis.com/projects/test-cat-findings-clseclab/zones/us-central1-a/clusters/ex-abuse-cluster-3",
				"state": "ACTIVE",
				"category": "WEB_UI_ENABLED",
				"externalUri": "https://console.cloud.google.com/kubernetes/clusters/details/us-central1-a/ex-abuse-cluster-3?project=test-cat-findings-clseclab",
				"sourceProperties": {
					"ReactivationCount": 0,
					"ExceptionInstructions": "Add the security mark \"allow_web_ui_enabled\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
					"SeverityLevel": "High",
					"Recommendation": "Go to https://console.cloud.google.com/kubernetes/clusters/details/us-central1-a/ex-abuse-cluster-3?project=test-cat-findings-clseclab then click \"Edit\", click \"Add-ons\", and disable \"Kubernetes dashboard\". Note that a cluster cannot be modified while it is reconfiguring itself.",
					"ProjectId": "test-cat-findings-clseclab",
					"AssetCreationTime": "2018-09-26T23:57:19+00:00",
					"ScannerName": "CONTAINER_SCANNER",
					"ScanRunId": "2019-09-30T18:20:20.151-07:00",
					"Explanation": "The Kubernetes web UI is backed by a highly privileged Kubernetes Service Account, which can be abused if compromised. If you are already using the GCP console, the Kubernetes web UI extends your attack surface unnecessarily. Learn more about how to disable the Kubernetes web UI and other techniques for hardening your Kubernetes clusters at https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#disable_kubernetes_dashboard"
				},
				"securityMarks": {
					"name": "organizations/119612413569/sources/7086426792249889955/findings/18db063343328e25a3997efaa0126274/securityMarks"
				},
				"eventTime": "2019-10-01T01:20:20.151Z",
				"createTime": "2019-03-05T22:21:01.836Z"
			}
		}`
	)
	for _, tt := range []struct {
		name, projectID, zone, clusterID string
		bytes                            []byte
		expectedError                    error
	}{
		{name: "read", projectID: "test-cat-findings-clseclab", zone: "us-central1-a", clusterID: "ex-abuse-cluster-3", bytes: []byte(webUIFinding), expectedError: nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := New(tt.bytes)
			if tt.expectedError == nil && err != nil {
				t.Errorf("%s failed: %q", tt.name, err)
			}
			if tt.expectedError != nil && err != nil && !xerrors.Is(err, tt.expectedError) {
				t.Errorf("%s failed: got:%q want:%q", tt.name, err, tt.expectedError)
			}
			values := r.DisableDashboard()
			if err == nil && r != nil && values.ProjectID != tt.projectID {
				t.Errorf("%s failed: got:%q want:%q", tt.name, values.ProjectID, tt.projectID)
			}
			if err == nil && r != nil && values.Zone != tt.zone {
				t.Errorf("%s failed: got:%q want:%q", tt.name, values.Zone, tt.zone)
			}
			if err == nil && r != nil && values.ClusterID != tt.clusterID {
				t.Errorf("%s failed: got:%q want:%q", tt.name, values.ClusterID, tt.clusterID)
			}
		})
	}
}
