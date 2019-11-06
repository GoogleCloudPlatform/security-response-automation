// Package main runs a Cloud Function locally.
package main

import (
	"context"
	"log"

	"cloud.google.com/go/pubsub"
	exec "github.com/googlecloudplatform/threat-automation"
)

const (
	finding = `{
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
)

func main() {
	ctx := context.Background()
	if err := exec.SnapshotDisk(ctx, pubsub.Message{Data: []byte(finding)}); err != nil {
		log.Fatal(err)
	}
}
