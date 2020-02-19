package containerscanner

import (
	"testing"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gke/disabledashboard"
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
		webUIFindingRemediated = `{
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
					"name": "organizations/119612413569/sources/7086426792249889955/findings/18db063343328e25a3997efaa0126274/securityMarks",
					"marks": {
						"sra-remediated-event-time": "2019-10-01T01:20:20.151Z"
				  	}
				},
				"eventTime": "2019-10-01T01:20:20.151Z",
				"createTime": "2019-03-05T22:21:01.836Z"
			}
		}`
		errorMessage = "remediation ignored! Finding already processed and remediated. Security Mark: \"sra-remediated-event-time: 2019-10-01T01:20:20.151Z\""
	)
	extractedValues := &disabledashboard.Values{
		ProjectID: "test-cat-findings-clseclab",
		Zone:      "us-central1-a",
		ClusterID: "ex-abuse-cluster-3",
		Mark:      "2019-10-01T01:20:20.151Z",
		Name:      "organizations/119612413569/sources/7086426792249889955/findings/18db063343328e25a3997efaa0126274",
	}
	for _, tt := range []struct {
		name           string
		ruleName       string
		values         *disabledashboard.Values
		bytes          []byte
		expectedErrMsg string
	}{
		{name: "read", ruleName: "web_ui_enabled", values: extractedValues, bytes: []byte(webUIFinding), expectedErrMsg: ""},
		{name: "remediated", ruleName: "", values: nil, bytes: []byte(webUIFindingRemediated), expectedErrMsg: errorMessage},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := New(tt.bytes)
			if err != nil && err.Error() != tt.expectedErrMsg {
				t.Errorf("%s failed: got:%q want:%q", tt.name, err, tt.expectedErrMsg)
			}
			if r != nil {
				if values := r.DisableDashboard(); *values != *tt.values {
					t.Errorf("%s failed: got:%v want:%v", tt.name, values, tt.values)
				}
				if name := r.Name(tt.bytes); name != tt.ruleName {
					t.Errorf("%q got:%q want:%q", tt.name, name, tt.ruleName)
				}
			}
		})
	}
}
