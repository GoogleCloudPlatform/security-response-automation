package turbinia

// Copyright 2020 Google LLC
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
	"github.com/google/uuid"
	"github.com/googlecloudplatform/security-response-automation/services"
)

const turbiniaRequestType = "TurbiniaRequest"

// GoogleCloudDisk represents a GCP disk.
type GoogleCloudDisk struct {
	Project  string `json:"project"`
	Zone     string `json:"zone"`
	DiskName string `json:"disk_name"`
}

// TurbiniaRequest is a request to send to Turbinia.
type TurbiniaRequest struct {
	RequestID string            `json:"request_id"`
	Type      string            `json:"type"`
	Evidence  []GoogleCloudDisk `json:"evidence"`
}

// Services contains the services needed for this function.
type Services struct {
	PubSub *services.PubSub
	Logger *services.Logger
}

// Values contains the required values needed for this function.
type Values struct {
	ProjectID string `yaml:"project_id"`
	Topic     string
	Zone      string
	DiskNames []string
}

// Execute will send the disks to Turbinia.
func Execute(ctx context.Context, values *Values, s *Services) error {
	for _, d := range values.DiskNames {
		b, err := buildRequest(values.ProjectID, values.Zone, d)
		if err != nil {
			return err
		}
		log.Printf("sending disk %q to Turbinia project %q", d, values.ProjectID)
		if _, err := s.PubSub.Publish(ctx, values.Topic, &pubsub.Message{
			Data: b,
		}); err != nil {
			return err
		}
	}
	return nil
}

func buildRequest(projectID, zone, diskName string) ([]byte, error) {
	var req TurbiniaRequest
	req.RequestID = uuid.New().String()
	req.Type = turbiniaRequestType
	req.Evidence = []GoogleCloudDisk{
		{
			Project:  projectID,
			Zone:     zone,
			DiskName: diskName,
		},
	}
	return json.Marshal(req)
}
