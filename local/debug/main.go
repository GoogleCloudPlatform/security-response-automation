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
)

func main() {
	ctx := context.Background()
	if err := exec.SnapshotDisk(ctx, pubsub.Message{Data: []byte(badIP)}); err != nil {
		log.Fatal(err)
	}
	if err := exec.OpenFirewall(ctx, pubsub.Message{Data: []byte(sshBruteForce)}); err != nil {
		log.Fatal(err)
	}
}
