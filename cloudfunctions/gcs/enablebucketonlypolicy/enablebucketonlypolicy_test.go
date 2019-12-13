package enablebucketonlypolicy

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

	"cloud.google.com/go/iam"
	"github.com/googlecloudplatform/security-response-automation/clients/stubs"
	"github.com/googlecloudplatform/security-response-automation/services"
	crm "google.golang.org/api/cloudresourcemanager/v1"
)

func TestEnableBucketOnlyPolicy(t *testing.T) {
	ctx := context.Background()

	test := []struct {
		name      string
		folderIDs []string
		expected  string
		ancestry  *crm.GetAncestryResponse
	}{
		{
			name:      "enable bucket only policy",
			folderIDs: []string{"123"},
			expected:  "bucket-to-enable-policy",
			ancestry:  services.CreateAncestors([]string{"folder/123"}),
		},
		{
			name:      "no folders",
			folderIDs: nil,
			expected:  "",
			ancestry:  services.CreateAncestors([]string{"folder/123"}),
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			svcs, crmStub, storageStub := enableBucketOnlyPolicySetup(tt.folderIDs)
			crmStub.GetAncestryResponse = tt.ancestry

			values := &Values{
				ProjectID:  "project-name",
				BucketName: "bucket-to-enable-policy",
			}

			if err := Execute(ctx, values, &Services{
				Configuration: svcs.Configuration,
				Resource:      svcs.Resource,
				Logger:        svcs.Logger,
			}); err != nil {
				t.Errorf("%s test failed want:%q", tt.name, err)
			}

			if tt.expected != "" {
				if s := storageStub.EnabledPolicyOnBucket; s != tt.expected {
					t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expected, s)
				}
			}
		})
	}
}

func enableBucketOnlyPolicySetup(folderIDs []string) (*services.Global, *stubs.ResourceManagerStub, *stubs.StorageStub) {
	loggerStub := &stubs.LoggerStub{}
	log := services.NewLogger(loggerStub)
	crmStub := &stubs.ResourceManagerStub{}
	storageStub := &stubs.StorageStub{}
	res := services.NewResource(crmStub, storageStub)
	storageStub.BucketPolicyResponse = &iam.Policy{}
	conf := &services.Configuration{
		EnableBucketOnlyPolicy: &services.EnableBucketOnlyPolicy{
			Resources: &services.Resources{
				FolderIDs: folderIDs,
			},
		},
	}
	return &services.Global{Logger: log, Resource: res, Configuration: conf}, crmStub, storageStub
}
