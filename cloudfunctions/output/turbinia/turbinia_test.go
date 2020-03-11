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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/googlecloudplatform/security-response-automation/clients/stubs"
	"github.com/googlecloudplatform/security-response-automation/services"
)

func TestTurbinia(t *testing.T) {

	crmStub := &stubs.ResourceManagerStub{}
	ancestryResponse := services.CreateAncestors([]string{"project/test-project", "folder/123", "organization/456"})
	crmStub.GetAncestryResponse = ancestryResponse

	var req RequestTurbinia
	req.RequestID = uuid.New().String()
	req.Type = turbiniaRequestType
	req.Requester = "Security Response Automation"
	req.Evidence = []GoogleCloudDisk{
		{
			Project:   "turbinia-tests-20200207",
			Zone:      "us-central1-a",
			DiskName:  "forensic_test",
			CloudOnly: true,
			Copyable:  true,
			Name:      "forensic_test",
			Type:      "GoogleCloudDisk",
			RequestID: req.RequestID,
		},
	}
	jsonReq, _ := json.Marshal(req)

	val := &Values{
		DiskNames: []string{"forensic_test"},
		RequestID: req.RequestID,
		Project:   "turbinia-tests-20200207",
		Topic:     "turbinia",
		Zone:      "us-central1-a",
	}

	for _, tt := range []struct {
		name    string
		values  *Values
		request []byte
	}{
		{
			name:    "turbinia only one disk",
			values:  val,
			request: jsonReq,
		},
	} {
		ctx := context.Background()
		psStub := &stubs.PubSubStub{}
		ps := services.NewPubSub(psStub)

		t.Run(tt.name, func(t *testing.T) {
			if err := Execute(ctx, tt.values, &Services{PubSub: ps, Logger: services.NewLogger(&stubs.LoggerStub{})}); err != nil {
				t.Errorf("%q failed: %q", tt.name, err)
			}

			if diff := cmp.Diff(string(tt.request), string(psStub.PublishedMessage.Data)); diff != "" {
				t.Errorf("%v failed, difference: %+v", tt.name, diff)
			}
		})
	}
}
