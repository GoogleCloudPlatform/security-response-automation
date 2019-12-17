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
)

func TestEnableBucketOnlyPolicy(t *testing.T) {
	ctx := context.Background()

	test := []struct {
		name     string
		expected string
	}{
		{
			name:     "enable bucket only policy",
			expected: "bucket-to-enable-policy",
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			svcs, storageStub := enableBucketOnlyPolicySetup()
			values := &Values{
				ProjectID:  "project-name",
				BucketName: "bucket-to-enable-policy",
			}

			if err := Execute(ctx, values, &Services{
				Resource: svcs.Resource,
				Logger:   svcs.Logger,
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

func enableBucketOnlyPolicySetup() (*services.Global, *stubs.StorageStub) {
	loggerStub := &stubs.LoggerStub{}
	log := services.NewLogger(loggerStub)
	crmStub := &stubs.ResourceManagerStub{}
	storageStub := &stubs.StorageStub{}
	res := services.NewResource(crmStub, storageStub)
	storageStub.BucketPolicyResponse = &iam.Policy{}
	return &services.Global{Logger: log, Resource: res}, storageStub
}
