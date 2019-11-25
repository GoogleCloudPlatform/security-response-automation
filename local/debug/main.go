// Package main runs a Cloud Function locally.
package main

import (
	"context"
	"log"

	"cloud.google.com/go/pubsub"
	exec "github.com/googlecloudplatform/security-response-automation"
)

const (
	badIP = `{
		"jsonPayload": {
			"properties": {
				"location": "us-central1",
				"project_id": "dark-shade",
				"instanceDetails": "/zones/us-central1-c/instances/instance-2"
			},
			"detectionCategory": {
				"ruleName": "bad_ip"
			}
		},
		"logName": "projects/test-project/logs/threatdetection.googleapis.com` + "%%2F" + `detection"
	}`
	sshBruteForce = `{
		"jsonPayload": {
		  "properties": {
				"location": "us-central1",
				"project_id": "dark-shade",
				"instanceDetails": "/zones/us-central1-c/instances/instance-2",
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
	sccAnoumalousIAMGrant = `{
		  "notificationConfigName": "organizations/1055058813388/notificationConfigs/noticonf-active-001-id",
		  "finding": {
			"name": "organizations/1055058813388/sources/6961325004191864574/findings/6a30ce604c11417995b1fa260753f3b5\t",
			"parent": "organizations/1055058813388/sources/6961325004191864574",
			"resourceName": "//cloudresourcemanager.googleapis.com/projects/714841595327",
			"state": "ACTIVE",
			"category": "Persistence: IAM Anomalous Grant",
			"externalUri": "https://console.cloud.google.com/home?project=long-carving-258319",
			"sourceProperties": {
			  "detectionCategory_indicator": "audit_log",
			  "detectionCategory_subRuleName": "external_member_added_to_policy",
			  "sourceId_customerOrganizationNumber": "1055058813388",
			  "evidence_0_sourceLogId_timestamp": "2019-11-22T18:34:34.953Z",
			  "detectionCategory_ruleName": "iam_anomalous_grant",
			  "properties_bindingDeltas_0_action": "ADD",
			  "detectionPriority": "HIGH",
			  "findingId": "6a30ce604c11417995b1fa260753f3b5",
			  "detectionCategory_technique": "persistence",
			  "properties_bindingDeltas_0_role": "roles/editor",
			  "evidence_0_sourceLogId_insertId": "-xagwy2da2ys",
			  "properties_principalEmail": "walves@clsecteam.com",
			  "properties_project_id": "long-carving-258319",
			  "sourceId_projectNumber": "714841595327",
			  "properties_bindingDeltas_1_action": "ADD",
			  "eventTime": "2019-11-22T18:34:36.153Z",
			  "properties_bindingDeltas_1_member": "user:weslleyassumpcao@gmail.com",
			  "properties_bindingDeltas_1_role": "roles/editor",
			  "affectedResources_0_gcpResourceName": "//cloudresourcemanager.googleapis.com/projects/714841595327",
			  "properties_externalMembers_1": "user:weslleyassumpcao@gmail.com",
			  "properties_bindingDeltas_0_member": "user:danielsandrade@gmail.com",
			  "properties_externalMembers_0": "user:danielsandrade@gmail.com"
			},
			"securityMarks": {},
			"eventTime": "2019-11-22T18:34:36.153Z",
			"createTime": "2019-11-22T18:34:36.688Z"
	  	}
	}`
)

func main() {
	ctx := context.Background()
	if err := exec.IAMRevoke(ctx, pubsub.Message{Data: []byte(sccAnoumalousIAMGrant)}); err != nil {
		log.Fatal(err)
	}
	//if err := exec.SnapshotDisk(ctx, pubsub.Message{Data: []byte(badIP)}); err != nil {
	//	log.Fatal(err)
	//}
	//if err := exec.OpenFirewall(ctx, pubsub.Message{Data: []byte(sshBruteForce)}); err != nil {
	//	log.Fatal(err)
	//}
}
