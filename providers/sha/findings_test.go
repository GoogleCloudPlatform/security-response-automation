package sha

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
	"testing"

	"cloud.google.com/go/pubsub"
	"github.com/pkg/errors"
)

const (
	shaFinding = `{
  "notificationConfigName": "organizations/154584661726/notificationConfigs/sampleConfigId",
  "finding": {
    "name": "organizations/154584661726/sources/2673592633662526977/findings/3d71012c3b3951c62e61b105e002f12b",
    "parent": "organizations/154584661726/sources/2673592633662526977",
    "resourceName": "//cloudresourcemanager.googleapis.com/projects/997507777601",
    "state": "ACTIVE",
    "category": "ADMIN_SERVICE_ACCOUNT",
    "externalUri": "https://console.cloud.google.com/iam-admin/iam?project=aerial-jigsaw-235219",
    "sourceProperties": {
      "ReactivationCount": 0,
      "OffendingIamRoles": "{\"invalidRoles\":[{\"user\":\"serviceAccount:automation-service-account@aerial-jigsaw-235219.iam.gserviceaccount.com\",\"roles\":[\"roles/pubsub.admin\"]},{\"user\":\"serviceAccount:service-997507777601@containerregistry.iam.gserviceaccount.com\",\"roles\":[\"roles/owner\"]}]}",
      "ExceptionInstructions": "Add the security mark \"allow_admin_service_account\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
      "SeverityLevel": "Medium",
      "Recommendation": "Go to https://console.cloud.google.com/iam-admin/iam?project=aerial-jigsaw-235219 to review the policy. The following accounts have admin or owner roles: [serviceAccount:automation-service-account@aerial-jigsaw-235219.iam.gserviceaccount.com, serviceAccount:service-997507777601@containerregistry.iam.gserviceaccount.com]",
      "ProjectId": "aerial-jigsaw-235219",
      "AssetCreationTime": "2019-03-21t19:41:58.502z",
      "ScannerName": "IAM_SCANNER",
      "ScanRunId": "2019-09-25T19:50:20.831-07:00",
      "Explanation": "A service account has owner or admin privileges. It is recommended for privilege for privilege separation that no service accounts have Admin or Owner permissions."
    },
    "securityMarks": {
      "name": "organizations/154584661726/sources/2673592633662526977/findings/3d71012c3b3951c62e61b105e002f12b/securityMarks"
    },
    "eventTime": "2019-09-26T02:50:20.831Z",
    "createTime": "2019-09-23T18:50:37.131Z"
  }
}`

	firewallFinding = `{
  "notificationConfigName": "organizations/154584661726/notificationConfigs/sampleConfigId",
  "finding": {
    "name": "organizations/154584661726/sources/2673592633662526977/findings/b16185f412d8a9b89d5615827f095df7",
    "parent": "organizations/154584661726/sources/2673592633662526977",
    "resourceName": "//compute.googleapis.com/projects/potent-minutia-246715/global/firewalls/8415669281173672995",
    "state": "ACTIVE",
    "category": "OPEN_FIREWALL",
    "externalUri": "https://console.cloud.google.com/networking/firewalls/details/allow-mysql-3306?project=potent-minutia-246715",
    "sourceProperties": {
      "ReactivationCount": 0,
      "Allowed": "[{\"IPProtocol\":\"tcp\",\"ipProtocol\":\"tcp\",\"port\":[\"3306\"],\"ports\":[\"3306\"]}]",
      "ExceptionInstructions": "Add the security mark \"allow_open_firewall\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
      "SeverityLevel": "High",
      "SourceRanges": "[\"0.0.0.0/0\"]",
      "Recommendation": "Restrict the firewall rules at: https://console.cloud.google.com/networking/firewalls/details/allow-mysql-3306?project=potent-minutia-246715",
      "AllowedIpRange": "All",
      "ActivationTrigger": "Allows all IP addresses",
      "ProjectId": "potent-minutia-246715",
      "AssetCreationTime": "2019-07-14t15:21:00.535-07:00",
      "ScannerName": "FIREWALL_SCANNER",
      "ScanRunId": "2019-09-23T15:10:56.633-07:00",
      "Explanation": "Firewall rules that allow connections from all IP addresses or on all ports may expose resources to attackers."
    },
    "securityMarks": {
      "name": "organizations/154584661726/sources/2673592633662526977/findings/b16185f412d8a9b89d5615827f095df7/securityMarks",
      "marks": {
        "f": "f"
      }
    },
    "eventTime": "2019-09-23T22:10:56.633Z",
    "createTime": "2019-09-23T17:20:28.054Z"
  }
}`

	publicBucketFinding = `{
  "notificationConfigName": "organizations/154584661726/notificationConfigs/sampleConfigId",
  "finding": {
    "name": "organizations/154584661726/sources/2673592633662526977/findings/782e52631d61da6117a3772137c270d8",
    "parent": "organizations/154584661726/sources/2673592633662526977",
    "resourceName": "//storage.googleapis.com/this-is-public-on-purpose",
    "state": "ACTIVE",
    "category": "PUBLIC_BUCKET_ACL",
    "externalUri": "https://console.cloud.google.com/storage/browser/this-is-public-on-purpose",
    "sourceProperties": {
      "ReactivationCount": 0.0,
      "ExceptionInstructions": "Add the security mark \"allow_public_bucket_acl\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
      "SeverityLevel": "High",
      "Recommendation": "Go to https://console.cloud.google.com/storage/browser/this-is-public-on-purpose, click on the Permissions tab, and remove \"allUsers\" and \"allAuthenticatedUsers\" from the bucket's members.",
      "ProjectId": "aerial-jigsaw-235219",
      "AssetCreationTime": "2019-09-19T20:08:29.102Z",
      "ScannerName": "STORAGE_SCANNER",
      "ScanRunId": "2019-09-23T10:20:27.204-07:00",
      "Explanation": "This bucket is public and can be accessed by anyone on the Internet. \"allUsers\" represents anyone on the Internet, and \"allAuthenticatedUsers\" represents anyone who is authenticated with a Google account; neither is constrained to users within your organization."
    },
    "securityMarks": {
      "name": "organizations/154584661726/sources/2673592633662526977/findings/782e52631d61da6117a3772137c270d8/securityMarks",
      "marks": {
        "babab": "3"
      }
    },
    "eventTime": "2019-09-23T17:20:27.204Z",
    "createTime": "2019-09-23T17:20:27.934Z"
  }
}`
)

// TestForFailures attempts to unmarshal logs that are not valid.
func TestForShaFailures(t *testing.T) {
	test := []struct {
		name    string
		message *pubsub.Message
		exp     error
	}{
		{
			"empty message",
			&pubsub.Message{},
			errors.New("on NewFirewallScanner: failed to unmarshal: unexpected end of JSON input"),
		},
		{
			"missing Source properties body",
			&pubsub.Message{Data: []byte(`{
				"finding": { "sourceProperties":}}`)},
			errors.New("on NewFirewallScanner: failed to unmarshal: invalid character '}' looking for beginning of value"),
		},
		{
			"it does not have a resource name",
			&pubsub.Message{Data: []byte(`{
				"finding": {
					"sourceProperties": {
						"ScannerName": "IAM_SCANNER"
					}}}`)},
			errors.New("on NewFirewallScanner: does not have a resource name: value not found"),
		},
		{
			"not a FIREWALL_SCANNER rule Finding",
			&pubsub.Message{Data: []byte(`{
				"finding": { 
					"resourceName": "//compute.googleapis.com/projects/teste-project/global/firewalls/6190685430815455733",
					"category": "CLOSE_FIREWALL",
					"sourceProperties": {
						"ScannerName": "IAM_SCANNER",
						"ProjectId": "teste-project" 
					}}}`)},
			errors.New("not a FIREWALL_SCANNER Finding: value not found"),
		},
		{
			"missing a project id",
			&pubsub.Message{Data: []byte(`{
				"finding": {
					"resourceName": "//compute.googleapis.com/projects/teste-project/global/firewalls/6190685430815455733",
					"category": "OPEN_FIREWALL",
					"sourceProperties": {
						"ScannerName": "FIREWALL_SCANNER"
					}}}`)},
			errors.New("does not have a project id: value not found"),
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewFirewallScanner(tt.message)
			if err.Error() != tt.exp.Error() {
				t.Errorf("exp:%q got: %q", tt.exp, err)
			}
		})
	}
}

func TestShaSuccess(t *testing.T) {
	test := []struct {
		name    string
		message *pubsub.Message
	}{
		{
			"valid finding",
			&pubsub.Message{Data: []byte(`{ 
				"notificationConfigName": "organizations/1055058813388/notificationConfigs/noticonf-active-001-id",
				"finding": {
				  "name": "organizations/1055058813388/sources/1986930501971458034/findings/cea981dd340112213827902b408b497e", 
				  "parent": "organizations/1055058813388/sources/1986930501971458034",  
				  "resourceName": "//compute.googleapis.com/projects/onboarding-pedro/global/firewalls/6190685430815455733",
				  "state": "ACTIVE", 
				  "category": "OPEN_FIREWALL",
				  "externalUri": "https://console.cloud.google.com/networking/firewalls/details/default-allow-http?project\u003donboarding-pedro",  
				  "sourceProperties": { 
					"ReactivationCount": 0.0,
					"Allowed": "[{\"IPProtocol\":\"tcp\",\"ipProtocol\":\"tcp\",\"port\":[\"80\"],\"ports\":[\"80\"]}]", 
					"ExceptionInstructions": "Add the security mark \"allow_open_firewall\" to the asset with a value of \"true\" to prevent this finding from being activated again.", 
					"SeverityLevel": "High",
					"Recommendation": "Restrict the firewall rules at: https://console.cloud.google.com/networking/firewalls/details/default-allow-http?project\u003donboarding-pedro", 
					"AllowedIpRange": "All",
					"ActivationTrigger": "Allows all IP addresses",
					"ProjectId": "onboarding-pedro",
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
			  }`)},
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewFirewallScanner(tt.message); err != nil {
				t.Errorf("exp: nil got:%q", err)
			}
		})
	}
}

func TestShaReadProjectID(t *testing.T) {
	test := []struct {
		name      string
		message   *pubsub.Message
		projectID string
	}{
		{
			"Read ProjectID successfully",
			&pubsub.Message{Data: []byte(`{
				"finding": {
					"resourceName": "//compute.googleapis.com/projects/teste-project/global/firewalls/6190685430815455733",
					"category": "OPEN_FIREWALL",
					"sourceProperties": {
						"ScannerName": "FIREWALL_SCANNER",
						"ProjectId": "teste-project"
					}}}`)},
			"teste-project",
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewFirewallScanner(tt.message)
			if err != nil {
				t.Errorf("failed reading SHA finding: %q", err)
			}
			z := f.ProjectID()
			if z != tt.projectID {
				t.Errorf("%s failed got:%q want:%q", tt.name, z, tt.projectID)
			}
		})
	}
}

func TestShaReadResourceName(t *testing.T) {
	test := []struct {
		name         string
		message      *pubsub.Message
		resourceName string
	}{
		{
			"Read ResourceName successfully",
			&pubsub.Message{Data: []byte(`{
				"finding": {
					"resourceName": "//compute.googleapis.com/projects/teste-project/global/firewalls/6190685430815455733",
					"category": "OPEN_FIREWALL",
					"sourceProperties": {
						"ScannerName": "FIREWALL_SCANNER",
						"ProjectId": "teste-project"
					}}}`)},
			"//compute.googleapis.com/projects/teste-project/global/firewalls/6190685430815455733",
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewFirewallScanner(tt.message)
			if err != nil {
				t.Errorf("failed reading SHA finding: %q", err)
			}
			z := f.ResourceName()
			if z != tt.resourceName {
				t.Errorf("%s failed got:%q want:%q", tt.name, z, tt.resourceName)
			}
		})
	}
}

func TestShaReadCategory(t *testing.T) {
	test := []struct {
		name     string
		message  *pubsub.Message
		category string
	}{
		{
			"Read Category successfully",
			&pubsub.Message{Data: []byte(`{
				"finding": {
					"resourceName": "//compute.googleapis.com/projects/teste-project/global/firewalls/6190685430815455733",
					"category": "OPEN_FIREWALL",
					"sourceProperties": {
						"ScannerName": "FIREWALL_SCANNER",
						"ProjectId": "teste-project"
					}}}`)},
			"OPEN_FIREWALL",
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewFirewallScanner(tt.message)
			if err != nil {
				t.Errorf("failed reading SHA finding: %q", err)
			}
			z := f.Category()
			if z != tt.category {
				t.Errorf("%s failed got:%q want:%q", tt.name, z, tt.category)
			}
		})
	}
}

func TestShaReadScannerName(t *testing.T) {
	test := []struct {
		name        string
		message     *pubsub.Message
		scannerName string
	}{
		{
			"Read Category successfully",
			&pubsub.Message{Data: []byte(`{
				"finding": {
					"resourceName": "//compute.googleapis.com/projects/teste-project/global/firewalls/6190685430815455733",
					"category": "OPEN_FIREWALL",
					"sourceProperties": {
						"ScannerName": "FIREWALL_SCANNER",
						"ProjectId": "teste-project"
					}}}`)},
			"FIREWALL_SCANNER",
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewFirewallScanner(tt.message)
			if err != nil {
				t.Errorf("failed reading SHA finding: %q", err)
			}
			z := f.ScannerName()
			if z != tt.scannerName {
				t.Errorf("%s failed got:%q want:%q", tt.name, z, tt.scannerName)
			}
		})
	}
}

func TestShaReadFirewallID(t *testing.T) {
	test := []struct {
		name       string
		message    *pubsub.Message
		firewallID string
	}{
		{
			"Read ResourceName successfully",
			&pubsub.Message{Data: []byte(`{
				"finding": {
					"resourceName": "//compute.googleapis.com/projects/teste-project/global/firewalls/6190685430815455733",
					"category": "OPEN_FIREWALL",
					"sourceProperties": {
						"ScannerName": "FIREWALL_SCANNER",
						"ProjectId": "teste-project"
					}}}`)},
			"6190685430815455733",
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewFirewallScanner(tt.message)
			if err != nil {
				t.Errorf("failed reading SHA finding: %q", err)
			}
			z := f.FirewallID()
			if z != tt.firewallID {
				t.Errorf("%s failed got:%q want:%q", tt.name, z, tt.firewallID)
			}
		})
	}
}

// TestForShaIamScanner attempts to read IAM scanner findings.
func TestForShaIamScanner(t *testing.T) {
	test := []struct {
		name           string
		message        *pubsub.Message
		expScannerName string
		expProjectID   string
	}{
		{name: "valid finding", message: &pubsub.Message{Data: []byte(shaFinding)}, expScannerName: "IAM_SCANNER", expProjectID: "aerial-jigsaw-235219"},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			f, _ := NewIamScanner(tt.message)
			if f.ScannerName() != tt.expScannerName {
				t.Errorf("%s failed got:%q want:%q", tt.name, f.ScannerName(), tt.expScannerName)
			}
			if f.ProjectID() != tt.expProjectID {
				t.Errorf("%s failed got:%q want:%q", tt.name, f.ProjectID(), tt.expProjectID)
			}
		})
	}
}

// TestForShaOpenFirewall attempts to read OpenFirewall findings.
func TestForShaOpenFirewall(t *testing.T) {
	test := []struct {
		name           string
		message        *pubsub.Message
		expScannerName string
		expProjectID   string
	}{
		{name: "valid finding", message: &pubsub.Message{Data: []byte(firewallFinding)}, expScannerName: "FIREWALL_SCANNER", expProjectID: "potent-minutia-246715"}}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			f, _ := NewFirewallScanner(tt.message)
			if f.ScannerName() != tt.expScannerName {
				t.Errorf("%s failed got:%q want:%q", tt.name, f.ScannerName(), tt.expScannerName)
			}
			if f.ProjectID() != tt.expProjectID {
				t.Errorf("%s failed got:%q want:%q", tt.name, f.ProjectID(), tt.expProjectID)
			}
		})
	}
}

// TestForShaPublicBucket attempts to read public bucket findings.
func TestForShaPublicBucket(t *testing.T) {
	test := []struct {
		name           string
		message        *pubsub.Message
		expScannerName string
		expProjectID   string
		expCategory    string
	}{
		{name: "valid finding", message: &pubsub.Message{Data: []byte(publicBucketFinding)}, expScannerName: "STORAGE_SCANNER", expProjectID: "aerial-jigsaw-235219", expCategory: "PUBLIC_BUCKET_ACL"}}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewStorageScanner(tt.message)
			if err != nil {
				t.Errorf("%s failed to read finding:%q", tt.name, err)
			}
			if f.Category() != tt.expCategory {
				t.Errorf("%s failed got:%q want:%q", tt.name, f.Category(), tt.expCategory)
			}
			if f.ScannerName() != tt.expScannerName {
				t.Errorf("%s failed got:%q want:%q", tt.name, f.ScannerName(), tt.expScannerName)
			}
			if f.ProjectID() != tt.expProjectID {
				t.Errorf("%s failed got:%q want:%q", tt.name, f.ProjectID(), tt.expProjectID)
			}
		})
	}
}
