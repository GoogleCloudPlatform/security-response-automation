package services

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
	"github.com/google/uuid"
	"github.com/pkg/errors"
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

// SendTurbinia will send the disks to Turbinia.
func SendTurbinia(ctx context.Context, turbiniaProjectID, topic, zone string, diskNames []string) error {
	if turbiniaProjectID == "" || topic == "" || zone == "" {
		return errors.New("missing turbinia config values")
	}
	m := &pubsub.Message{}
	ps, err := InitPubSub(ctx, turbiniaProjectID)
	if err != nil {
		return err
	}
	for _, diskName := range diskNames {
		b, err := buildRequest(turbiniaProjectID, zone, diskName)
		if err != nil {
			return err
		}
		m.Data = b
		log.Printf("sending disk %q to turbinia project %q", diskName, turbiniaProjectID)
		if _, err := ps.Publish(ctx, topic, m); err != nil {
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
