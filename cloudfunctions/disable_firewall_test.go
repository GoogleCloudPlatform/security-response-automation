package cloudfunctions

import "cloud.google.com/go/pubsub"

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

var (
	sampleShaFinding = pubsub.Message{Data: []byte(`{
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
	}`)}
)
