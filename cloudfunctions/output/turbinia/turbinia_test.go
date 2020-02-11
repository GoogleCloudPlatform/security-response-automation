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
	"testing"

	"github.com/googlecloudplatform/security-response-automation/clients/stubs"
	"github.com/googlecloudplatform/security-response-automation/services"
)

func TestTurbinia(t *testing.T) {

	crmStub := &stubs.ResourceManagerStub{}
	ancestryResponse := services.CreateAncestors([]string{"project/test-project", "folder/123", "organization/456"})
	crmStub.GetAncestryResponse = ancestryResponse

	for _, tt := range []struct {
		name    string
		projectId  string
		zone  string
		topic string
		disknames []string
	}{
		{name: "turbinia only one disk", projectId: "turbinia-test-20200210", disknames: []string{"forensic_test"}, zone:"us-central1-a", topic: "turbinia"},
		{name: "turbinia multiple disks", projectId: "turbinia-test-20200210", disknames: []string{"forensic_test", "bad_ip_snapshoot"}, zone:"us-central1-a", topic: "turbinia"},
	} {
		ctx := context.Background()
		psStub := &stubs.PubSubStub{}
		ps := services.NewPubSub(psStub)

		t.Run(tt.name, func(t *testing.T) {

			if err := Execute(ctx, &Values{
				ProjectID: tt.projectId,
				Topic: tt.topic,
				Zone: tt.zone,
				DiskNames: tt.disknames,
			}, &Services{
				PubSub:        ps,
				Logger:        services.NewLogger(&stubs.LoggerStub{}),
			}); err != nil {
				t.Fatalf("%q failed: %q", tt.name, err)
			}
		})
	}


}
