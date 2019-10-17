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
	"log"
	"testing"

	"cloud.google.com/go/pubsub"
	"github.com/googlecloudplatform/threat-automation/entities"
	"github.com/pkg/errors"
	"golang.org/x/xerrors"
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

	publicIpAddressFinding = `{
  "notificationConfigName": "organizations/154584661726/notificationConfigs/sampleConfigId",
  "finding": {
	"name": "organizations/1055058813388/sources/1986930501971458034/findings/d7ef72093c8c1e4c135d4c43fa847b83",
	"parent": "organizations/1055058813388/sources/1986930501971458034",
	"resourceName": "//compute.googleapis.com/projects/sec-automation-dev/zones/us-central1-a/instances/4312755253150365851",
	"state": "ACTIVE",
	"category": "PUBLIC_IP_ADDRESS",
	"externalUri": "https://console.cloud.google.com/compute/instancesDetail/zones/us-central1-a/instances/remove-public-ip-test-vm",
	"sourceProperties": {
	  "ReactivationCount": 0,
	  "ExceptionInstructions": "Add the security mark \"allow_public_ip_address\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
	  "SeverityLevel": "High",
	  "Recommendation": "If this is unintended, please go to https://console.cloud.google.com/compute/instancesDetail/zones/us-central1-a/instances/remove-public-ip-test-vm and click \"Edit\". For each interface under the \"Network interfaces\" heading, set \"External IP\" to \"None\" or \"Ephemeral\", then click \"Done\" and \"Save\".  If you would like to learn more about securing access to your infrastructure, see https://cloud.google.com/solutions/connecting-securely.",
	  "ProjectId": "sec-automation-dev",
	  "AssetCreationTime": "2019-10-04T10:50:45.017-07:00",
	  "ScannerName": "COMPUTE_INSTANCE_SCANNER",
	  "ScanRunId": "2019-10-10T00:01:51.204-07:00",
	  "Explanation": "To reduce the attack surface, avoid assigning public IP addresses to your VMs."
	},
	"securityMarks": {
	  "name": "organizations/1055058813388/sources/1986930501971458034/findings/d7ef72093c8c1e4c135d4c43fa847b83/securityMarks",
	  "marks": {
		"kieras-test": "true",
		"kieras-test2": "true"
	  }
	},
	"eventTime": "2019-10-10T07:01:51.204Z",
	"createTime": "2019-10-04T19:02:25.582Z"
  }
}`
)

func TestForShaFailures(t *testing.T) {
	test := []struct {
		name    string
		message *pubsub.Message
		exp     error
	}{
		{
			name:    "empty message",
			message: &pubsub.Message{},
			exp:     entities.ErrUnmarshal,
		},
		{
			name: "missing properties",
			message: &pubsub.Message{Data: []byte(`{
				"finding": { "sourceProperties":}}`)},
			exp: entities.ErrUnmarshal,
		},
		{
			name: "missing required field resource name",
			message: &pubsub.Message{Data: []byte(`{
				"finding": {
					"sourceProperties": {
						"ScannerName": "IAM_SCANNER"
					}}}`)},
			exp: entities.ErrValueNotFound,
		},
		{
			name: "unknown scanner",
			message: &pubsub.Message{Data: []byte(`{
				"finding": { 
					"resourceName": "//compute.googleapis.com/projects/teste-project/global/firewalls/6190685430815455733",
					"category": "CLOSE_FIREWALL",
					"sourceProperties": {
						"ScannerName": "DOES_NOT_EXIST",
						"ProjectId": "teste-project" 
					}}}`)},
			exp: entities.ErrValueNotFound,
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewFinding(tt.message); !xerrors.Is(errors.Cause(err), tt.exp) {
				t.Errorf("%q failed want:%q got:%q", tt.name, tt.exp, errors.Cause(err))
			}
		})
	}
}

func TestShaSuccess(t *testing.T) {
	test := []struct {
		name            string
		message         *pubsub.Message
		expProjectID    string
		expResourceName string
		expCategory     string
		expScannerName  string
	}{
		{
			name:            "valid basic SHA finding",
			message:         &pubsub.Message{Data: []byte(shaFinding)},
			expProjectID:    "aerial-jigsaw-235219",
			expResourceName: "//cloudresourcemanager.googleapis.com/projects/997507777601",
			expCategory:     "ADMIN_SERVICE_ACCOUNT",
			expScannerName:  "IAM_SCANNER",
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewFinding(tt.message)
			if err != nil {
				t.Errorf("exp: nil got:%q", err)
			}
			if f != nil && f.ProjectID() != tt.expProjectID {
				t.Errorf("%s failed for ProjectID got:%q want:%q", tt.name, f.ProjectID(), tt.expProjectID)
			}
			if f != nil && f.ResourceName() != tt.expResourceName {
				t.Errorf("%s failed for ResourceName got:%q want:%q", tt.name, f.ResourceName(), tt.expResourceName)
			}
			if f != nil && f.Category() != tt.expCategory {
				t.Errorf("%s failed for Category got:%q want:%q", tt.name, f.Category(), tt.expCategory)
			}
			if f != nil && f.ScannerName() != tt.expScannerName {
				t.Errorf("%s failed for ScannerName got:%q want:%q", tt.name, f.ScannerName(), tt.expScannerName)
			}
		})
	}
}

func TestForShaFirewallScanner(t *testing.T) {
	test := []struct {
		name          string
		message       *pubsub.Message
		expFirewallID string
	}{
		{
			name:          "valid SHA Firewall Scanner finding",
			message:       &pubsub.Message{Data: []byte(firewallFinding)},
			expFirewallID: "8415669281173672995",
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewFinding(tt.message)
			if err != nil {
				t.Errorf("%s failed to read finding:%q", tt.name, err)
			}
			if f != nil && f.firewallScanner.FirewallID() != tt.expFirewallID {
				t.Errorf("%s failed for FirewallID got:%q want:%q", tt.name, f.firewallScanner.FirewallID(), tt.expFirewallID)
			}
		})
	}
}

func TestForShaIamScanner(t *testing.T) {
	test := []struct {
		name                 string
		message              *pubsub.Message
		expOffendingIamRoles string
	}{
		{
			name:                 "valid finding",
			message:              &pubsub.Message{Data: []byte(shaFinding)},
			expOffendingIamRoles: "{\"invalidRoles\":[{\"user\":\"serviceAccount:automation-service-account@aerial-jigsaw-235219.iam.gserviceaccount.com\",\"roles\":[\"roles/pubsub.admin\"]},{\"user\":\"serviceAccount:service-997507777601@containerregistry.iam.gserviceaccount.com\",\"roles\":[\"roles/owner\"]}]}",
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewFinding(tt.message)
			if err != nil {
				t.Errorf("%s failed to read finding:%q", tt.name, err)
			}
			log.Printf("%+v\n", f)
			if f != nil && f.IAMScanner.OffendingIamRoles() != tt.expOffendingIamRoles {
				t.Errorf("%s failed for OffendingIamRoles got:%q want:%q", tt.name, f.IAMScanner.OffendingIamRoles(), tt.expOffendingIamRoles)
			}
		})
	}
}

func TestForShaStorageScanner(t *testing.T) {
	test := []struct {
		name          string
		message       *pubsub.Message
		expBucketName string
	}{
		{
			name:          "valid SHA Storage Scanner finding",
			message:       &pubsub.Message{Data: []byte(publicBucketFinding)},
			expBucketName: "this-is-public-on-purpose",
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewFinding(tt.message)
			if err != nil {
				t.Errorf("%s failed to read finding:%q", tt.name, err)
			}
			if f != nil && f.StorageScanner.BucketName() != tt.expBucketName {
				t.Errorf("%s failed for BucketName got:%q want:%q", tt.name, f.StorageScanner.BucketName(), tt.expBucketName)
			}
		})
	}
}

func TestForShaComputeInstanceScanner(t *testing.T) {
	test := []struct {
		name        string
		message     *pubsub.Message
		expZone     string
		expInstance string
	}{
		{
			name:        "valid SHA Compute Instance Scanner finding",
			message:     &pubsub.Message{Data: []byte(publicIpAddressFinding)},
			expZone:     "us-central1-a",
			expInstance: "4312755253150365851",
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewFinding(tt.message)
			if err != nil {
				t.Errorf("%s failed to read finding:%q", tt.name, err)
			}
			if f != nil && f.ComputeInstanceScanner.Zone() != tt.expZone {
				t.Errorf("%s failed for Zone got:%q want:%q", tt.name, f.ComputeInstanceScanner.Zone(), tt.expZone)
			}
			if f != nil && f.ComputeInstanceScanner.Instance() != tt.expInstance {
				t.Errorf("%s failed for Instance got:%q want:%q", tt.name, f.ComputeInstanceScanner.Instance(), tt.expInstance)
			}
		})
	}
}
