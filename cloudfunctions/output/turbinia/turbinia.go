package turbinia

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
	"context"
	"encoding/json"
	"log"

	"cloud.google.com/go/pubsub"
	"github.com/googlecloudplatform/security-response-automation/services"
)

const turbiniaRequestType = "TurbiniaRequest"

// GoogleCloudDisk represents a GCP disk.
type GoogleCloudDisk struct {
	Project        string `json:"project"`
	Zone           string `json:"zone"`
	DiskName       string `json:"disk_name"`
	Name           string `json:"name"`
	RequestID      string `json:"request_id"`
	Type           string `json:"type"`
	Copyable       bool   `json:"copyable"`
	CloudOnly      bool   `json:"cloud_only"`
	LocalPath      string `json:"local_path"`
	SavedPath      string `json:"saved_path"`
	SavedPathType  string `json:"saved_path_type"`
	ParentEvidence string `json:"parent_evidence"`
}

// Recipe struct to TurbiniaRequest
type Recipe struct{}

// TurbiniaRequest is a request to send to Turbinia.
type TurbiniaRequest struct {
	RequestID string            `json:"request_id"`
	Type      string            `json:"type"`
	Evidence  []GoogleCloudDisk `json:"evidence"`
	Requester string            `json:"requester"`
	Context   string            `json:"context"`
	Recipe    Recipe            `json:"recipe"`
}

// Services contains the services needed for this function.
type Services struct {
	PubSub *services.PubSub
	Logger *services.Logger
}

// Values contains the required values needed for this function.
type Values struct {
	Project   string `yaml:"project_id"`
	Topic     string
	Zone      string
	DiskNames []string
	RequestId string
}

// Execute will send the disks to Turbinia.
func Execute(ctx context.Context, values *Values, services *Services) error {
	for _, d := range values.DiskNames {
		b, err := buildRequest(values.Project, values.Zone, d, values.RequestId)
		if err != nil {
			return err
		}
		log.Printf("sending disk %q to Turbinia project %q", d, values.Project)
		if _, err := services.PubSub.Publish(ctx, values.Topic, &pubsub.Message{Data: b}); err != nil {
			return err
		}
	}
	return nil
}

func buildRequest(projectID, zone, diskName string, requestId string) ([]byte, error) {
	var req TurbiniaRequest
	req.RequestID = requestId
	req.Type = turbiniaRequestType
	req.Requester = "Security Response Automation"
	req.Evidence = []GoogleCloudDisk{
		{
			Project:   projectID,
			Zone:      zone,
			DiskName:  diskName,
			CloudOnly: true,
			Copyable:  true,
			Name:      diskName,
			Type:      "GoogleCloudDisk",
			RequestID: req.RequestID,
		},
	}
	return json.Marshal(req)
}
