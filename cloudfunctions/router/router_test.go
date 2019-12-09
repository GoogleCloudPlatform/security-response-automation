package router

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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/googlecloudplatform/security-response-automation/clients/stubs"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/createsnapshot"
	"github.com/googlecloudplatform/security-response-automation/providers/etd/badip"
	"github.com/googlecloudplatform/security-response-automation/services"
)

func TestRouter(t *testing.T) {
	const (
		somethingElse = `{
			"jsonPayload": {
				"properties": {
					"location": "us-central1",
					"project_id": "test-project",
					"instanceDetails": "/zones/zone-name/instances/source-instance-name"
				}
			},
			"logName": "projects/test-project/logs/threatdetection.googleapis.com` + "%%2F" + `detection"
		}`
		validBadIP = `{
			"jsonPayload": {
				"properties": {
					"location": "us-central1",
					"project_id": "test-project",
					"instanceDetails": "/zones/zone-name/instances/source-instance-name"
				},
				"detectionCategory": {
					"ruleName": "bad_ip"
				}
			},
			"logName": "projects/test-project/logs/threatdetection.googleapis.com` + "%%2F" + `detection"
		}`
	)
	conf := &Configuration{}
	// BadIP findings should map to "gce_create_disk_snapshot".
	conf.Spec.Parameters.ETD.BadIP = []badip.Automation{
		{Action: "gce_create_disk_snapshot"},
	}
	createSnapshotValues := &createsnapshot.Values{
		ProjectID: "test-project",
		RuleName:  "bad_ip",
		Instance:  "source-instance-name",
		Zone:      "zone-name",
	}
	createSnapshot, _ := json.Marshal(createSnapshotValues)
	for _, tt := range []struct {
		name    string
		mapTo   []byte
		finding []byte
	}{
		{name: "bad_ip", finding: []byte(validBadIP), mapTo: createSnapshot},
	} {
		ctx := context.Background()
		psStub := &stubs.PubSubStub{}
		ps := services.NewPubSub(psStub)

		t.Run(tt.name, func(t *testing.T) {

			if err := Execute(ctx, &Values{
				Finding: tt.finding,
			}, &Services{
				PubSub:        ps,
				Configuration: conf,
			}); err != nil {
				t.Errorf("%q failed: %q", tt.name, err)
			}
			if diff := cmp.Diff(psStub.PublishedMessage.Data, tt.mapTo); diff != "" {
				t.Errorf("%q failed, difference:%+v", tt.name, diff)
			}
		})
	}
}
