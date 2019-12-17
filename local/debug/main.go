// Package main runs a Cloud Function locally.
package main

import (
	"context"
	"log"

	"cloud.google.com/go/pubsub"
	exec "github.com/googlecloudplatform/security-response-automation"
)

const (
	badIPCSCC = `{
		"notificationConfigName": "organizations/1037840971520/notificationConfigs/sampleConfigId",
		"finding": {
		  "name": "organizations/1037840971520/sources/15233230630886231666/findings/6cc800d88324478aa80d2031794214a4",
		  "parent": "organizations/1037840971520/sources/15233230630886231666",
		  "resourceName": "//cloudresourcemanager.googleapis.com/projects/459837319394",
		  "state": "ACTIVE",
		  "category": "C2: Bad IP",
		  "sourceProperties": {
			"properties_subnetwork_name": "default",
			"detectionCategory_ruleName": "bad_ip",
			"properties_project_id": "ae-threat-detection",
			"eventTime": "2019-12-11T22:39:54.657Z",
			"sourceId_projectNumber": "459837319394",
			"affectedResources_0_gcpResourceName": "//cloudresourcemanager.googleapis.com/projects/459837319394",
			"properties_ip_0": "80.82.64.214",
			"properties_location": "us-central1-a",
			"evidence_0_sourceLogId_timestamp": "2019-12-11T22:39:54.060661565Z",
			"detectionPriority": "HIGH",
			"properties_instanceDetails": "/projects/ae-threat-detection/zones/us-central1-a/instances/instance-1",
			"detectionCategory_technique": "C2",
			"findingId": "6cc800d88324478aa80d2031794214a4",
			"sourceId_customerOrganizationNumber": "1037840971520",
			"evidence_0_sourceLogId_insertId": "198cht8g3wedctq",
			"detectionCategory_indicator": "ip",
			"properties_subnetwork_id": "3951118263795572377"
		  },
		  "securityMarks": {
			"name": "organizations/1037840971520/sources/15233230630886231666/findings/6cc800d88324478aa80d2031794214a4/securityMarks",
			"marks": {
			  "k": "ok",
			  "adfs": "adf",
			  "adsf": "adsf"
			}
		  },
		  "eventTime": "2019-12-11T22:39:54.657Z",
		  "createTime": "2019-12-11T22:39:55.358Z"
		}
	}`
	badIP = `{
		"jsonPayload": {
			"properties": {
				"location": "us-central1",
				"project_id": "aerial-jigsaw-235219",
				"instanceDetails": "/zones/us-central1-a/instances/instance-4"
			},
			"detectionCategory": {
				"ruleName": "bad_ip"
			}
		},
		"logName": "projects/test-project/logs/threatdetection.googleapis.com` + "%%2F" + `detection"
	}`
	badIPValues = `{
		"ProjectID": "aerial-jigsaw-235219",
		"Instance": "instance-4",
		"Zone": "us-central1-a",
		"RuleName": "bad_ip",
		"DryRun": true,
		"Target": [],
		"Exclude": [],
		"Output": []
	}`
	sshBruteForce = `{
		"jsonPayload": {
		  "properties": {
				"location": "us-central1",
				"project_id": "dark-shade",
				"instanceDetails": "/zones/us-central1-c/instances/instance-",
				"project_id": "aerial-jigsaw-235219",
				"loginAttempts": [{
						"authResult": "FAIL",
						"sourceIp": "10.200.0.2",
						"userName": "okokok",
						"vmName": "ssh-password-auth-debian-9"
					}, {
						"authResult": "SUCCESS",
						"sourceIp": "10.200.0.2",
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
	iam = `{
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
		  "eventTime": "2019-12-12T22:42:36.720Z",
		  "evidence": [
			{
			  "sourceLogId": {
				"insertId": "28alkud1zr2",
				"timestamp": "2019-12-12T22:42:35.113Z"
			  }
			}
		  ],
		  "findingId": "829f7e10a7aa43f48c91c23407d3e16b",
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
		"receiveTimestamp": "2019-12-12T22:42:37.613334916Z",
		"resource": {
		  "labels": {
			"detector_name": "iam_anomalous_grant",
			"project_id": "aerial-jigsaw-235219"
		  },
		  "type": "threat_detector"
		},
		"severity": "CRITICAL",
		"timestamp": "2019-12-12T22:42:36.720Z"
	  }`
	publicBucket = `{
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

func main() {
	ctx := context.Background()
	// if err := exec.IAMRevoke(ctx, pubsub.Message{Data: []byte(`{
	// 	"ProjectID": "aerial-jigsaw-235219",
	// 	"ExternalMembers": [
	// 		"ccexperts@gmail.com"
	// 	]
	// }`)}); err != nil {
	// 	log.Fatal(err)
	// }
	// if err := exec.SnapshotDisk(ctx, pubsub.Message{Data: []byte(badIP)}); err != nil {
	// 	log.Fatal(err)
	// }
	// if err := exec.OpenFirewall(ctx, pubsub.Message{Data: []byte(sshBruteForce)}); err != nil {
	// 	log.Fatal(err)
	// }
	if err := exec.Router(ctx, pubsub.Message{Data: []byte(publicBucket)}); err != nil {
		log.Fatal(err)
	}
}
