package firewallscanner

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/openfirewall"
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
		openFirewallRemediated = `{
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
						"sra-remediated-event-time": "2019-09-19T16:58:39.276Z"
					}
				},
				"eventTime": "2019-09-19T16:58:39.276Z",
				"createTime": "2019-09-16T22:11:59.977Z"
			}
		}`
		errorMessage = "remediation ignored! Finding already processed and remediated. Security Mark: \"sra-remediated-event-time: 2019-09-19T16:58:39.276Z\""
	)
	extractedValues := &openfirewall.Values{
		ProjectID:  "onboarding-project",
		FirewallID: "6190685430815455733",
		Mark:       "2019-09-19T16:58:39.276Z",
		Name:       "organizations/1055058813388/sources/1986930501971458034/findings/cea981dd340112213827902b408b497e",
	}
	for _, tt := range []struct {
		name           string
		ruleName       string
		values         *openfirewall.Values
		bytes          []byte
		expectedErrMsg string
	}{
		{name: "read sha", ruleName: "open_firewall", values: extractedValues, bytes: []byte(openFirewallFinding), expectedErrMsg: ""},
		{name: "remediated", ruleName: "", values: nil, bytes: []byte(openFirewallRemediated), expectedErrMsg: errorMessage},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := New(tt.bytes)
			if err != nil && err.Error() != tt.expectedErrMsg {
				t.Errorf("%s failed: got:%q want:%q", tt.name, err, tt.expectedErrMsg)
			}
			if r != nil {
				values := r.OpenFirewall()
				if diff := cmp.Diff(values, tt.values); diff != "" {
					t.Errorf("%q failed, difference:%+v", tt.name, diff)
				}
				if name := r.Name(tt.bytes); name != tt.ruleName {
					t.Errorf("%q got:%q want:%q", tt.name, name, tt.ruleName)
				}
			}
		})
	}
}
