package main

import (
	"fmt"
	"os"

	exec "github.com/googlecloudplatform/threat-automation"

	"context"

	"cloud.google.com/go/pubsub"
)

var (
	// folderID specifies which folder RevokeExternalGrantsFolders should remove members from.
	folderIDs = []string{"670032686187"}
	// disallowed contains a list of external domains RevokeExternalGrantsFolders should remove.
	disallowed = []string{"test.com", "gmail.com"}
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
	anomalousIAMGrant = `{
		"insertId": "31y1f6a4",
		"jsonPayload": {
		  "affectedResources": [
			{
			  "gcpResourceName": "//cloudresourcemanager.googleapis.com/projects/997507777601"
			}
		  ],
		  "detectionCategory": {
			"indicator": "audit_log",
			"ruleName": "iam_anomalous_grant",
			"subRuleName": "external_member_added_to_policy",
			"technique": "persistence"
		  },
		  "detectionPriority": "HIGH",
		  "eventTime": "2019-09-09T18:25:49.236Z",
		  "evidence": [
			{
			  "sourceLogId": {
				"insertId": "-kt3q87c71s",
				"timestamp": "2019-09-09T18:25:47.409Z"
			  }
			}
		  ],
		  "properties": {
			"bindingDeltas": [
			  {
				"action": "ADD",
				"member": "user:ccexperts@gmail.com",
				"role": "roles/editor"
			  }
			],
			"externalMembers": [
			  "user:ccexperts@gmail.com"
			],
			"principalEmail": "tom3fitzgerald@gmail.com",
			"project_id": "aerial-jigsaw-235219"
		  },
		  "sourceId": {
			"customerOrganizationNumber": "154584661726",
			"projectNumber": "997507777601"
		  }
		},
		"logName": "projects/aerial-jigsaw-235219/logs/threatdetection.googleapis.com%2Fdetection",
		"receiveTimestamp": "2019-09-09T18:25:50.087113103Z",
		"resource": {
		  "labels": {
			"detector_name": "iam_anomalous_grant",
			"project_id": "aerial-jigsaw-235219"
		  },
		  "type": "threat_detector"
		},
		"severity": "CRITICAL",
		"timestamp": "2019-09-09T18:25:49.236Z"
		}`

	badIPFinding = `{
  "insertId": "-9fhc83a4",
  "jsonPayload": {
    "affectedResources": [
      {
        "gcpResourceName": "//cloudresourcemanager.googleapis.com/projects/aerial-jigsaw-235219"
      }
    ],
    "detectionCategory": {
      "indicator": "ip",
      "ruleName": "bad_ip",
      "technique": "cryptomining"
    },
    "detectionPriority": "HIGH",
    "eventTime": "2019-07-16T21:00:44.760Z",
    "evidence": [
      {
        "sourceLogId": {
          "insertId": "11qjm6ng183mguh",
          "timestamp": "2019-07-16T21:00:44.179635017Z"
        }
      }
    ],
    "properties": {
      "destinationInstance": "",
      "ip": [
        "52.8.47.33"
      ],
      "location": "us-central1-c",
      "project_id": "aerial-jigsaw-235219",
      "sourceInstance": "/projects/aerial-jigsaw-235219/zones/us-central1-c/instances/instance-2",
      "subnetwork_id": "288355645352614400",
      "subnetwork_name": "default"
    },
    "sourceId": {
      "customerOrganizationNumber": "154584661726",
      "projectNumber": "997507777601"
    }
  },
  "logName": "projects/aerial-jigsaw-235219/logs/threatdetection.googleapis.com%2Fdetection",
  "receiveTimestamp": "2019-07-16T21:00:45.913791943Z",
  "resource": {
    "labels": {
      "detector_name": "bad_ip",
      "project_id": "aerial-jigsaw-235219"
    },
    "type": "threat_detector"
  },
  "severity": "CRITICAL",
  "timestamp": "2019-07-16T21:00:44.760Z"
}`
)

func main() {
	ctx := context.Background()
	if err := exec.SnapshotDisk(ctx, pubsub.Message{Data: []byte(badIPFinding)}); err != nil {
		fmt.Printf("snapshost disk failed: %q", err)
		os.Exit(1)
	}
}
