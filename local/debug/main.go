// Package main runs a Cloud Function locally.
package main

import (
	"context"
	"log"

	"cloud.google.com/go/pubsub"
	exec "github.com/googlecloudplatform/security-response-automation"
)

const (
	badIPSD = `{
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
	badIPSCC = `{
		  "notificationConfigName": "organizations/0000000000000/notificationConfigs/noticonf-active-001-id",
		  "finding": {
			"name": "organizations/0000000000000/sources/0000000000000000000/findings/6a30ce604c11417995b1fa260753f3b5",
			"parent": "organizations/0000000000000/sources/0000000000000000000",
			"resourceName": "//cloudresourcemanager.googleapis.com/projects/000000000000",
			"state": "ACTIVE",
			"category": "C2: Bad IP",
			"externalUri": "https://console.cloud.google.com/home?project=test-project-15511551515",
			"sourceProperties": {
			  	"detectionCategory_ruleName": "bad_ip",
				"properties_project_id": "test-project-15511551515",
				"properties_instanceDetails": "/projects/test-project-15511551515/zones/us-central1-a/instances/bad-ip-caller",
				"properties_location": "us-central1-a"
			},
			"securityMarks": {},
			"eventTime": "2019-11-22T18:34:36.153Z",
			"createTime": "2019-11-22T18:34:36.688Z"
	  	}
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
)

func main() {
	ctx := context.Background()
	if err := exec.SnapshotDisk(ctx, pubsub.Message{Data: []byte(badIPSD)}); err != nil {
		log.Fatal(err)
	}
	if err := exec.SnapshotDisk(ctx, pubsub.Message{Data: []byte(badIPSCC)}); err != nil {
		log.Fatal(err)
	}
	if err := exec.OpenFirewall(ctx, pubsub.Message{Data: []byte(sshBruteForce)}); err != nil {
		log.Fatal(err)
	}
}
