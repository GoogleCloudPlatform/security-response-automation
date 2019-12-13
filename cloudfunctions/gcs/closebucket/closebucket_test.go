package closebucket

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
	"github.com/google/go-cmp/cmp"
	"github.com/googlecloudplatform/security-response-automation/clients/stubs"
	"github.com/googlecloudplatform/security-response-automation/services"
	crm "google.golang.org/api/cloudresourcemanager/v1"
)

func TestCloseBucket(t *testing.T) {
	ctx := context.Background()

	test := []struct {
		name           string
		initialMembers []string
		folderIDs      []string
		expected       []string
		ancestry       *crm.GetAncestryResponse
	}{
		{
			name:           "remove allUsers",
			initialMembers: []string{"allUsers", "member:tom@tom.com"},
			folderIDs:      []string{"123"},
			expected:       []string{"member:tom@tom.com"},
			ancestry:       services.CreateAncestors([]string{"folder/123"}),
		},
		{
			name:           "no folders",
			initialMembers: []string{"allUsers", "member:tom@tom.com"},
			folderIDs:      nil,
			expected:       nil,
			ancestry:       services.CreateAncestors([]string{"folder/123"}),
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			svcs, crmStub, storageStub := closeBucketSetup(tt.folderIDs)
			crmStub.GetAncestryResponse = tt.ancestry
			for _, v := range tt.initialMembers {
				storageStub.BucketPolicyResponse.Add(v, "project/viewer")
			}

			required := &Values{
				ProjectID:  "project-name",
				BucketName: "open-bucket-name",
			}

			if err := Execute(ctx, required, &Services{
				Configuration: svcs.Configuration,
				Resource:      svcs.Resource,
				Logger:        svcs.Logger,
			}); err != nil {
				t.Errorf("%s test failed want:%q", tt.name, err)
			}

			if tt.expected != nil {
				s := storageStub.RemoveBucketPolicy.Members("project/viewer")
				if diff := cmp.Diff(s, tt.expected); diff != "" {
					t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expected, s)
				}
			}
		})
	}
}

func closeBucketSetup(folderIDs []string) (*services.Global, *stubs.ResourceManagerStub, *stubs.StorageStub) {
	loggerStub := &stubs.LoggerStub{}
	log := services.NewLogger(loggerStub)
	crmStub := &stubs.ResourceManagerStub{}
	storageStub := &stubs.StorageStub{}
	res := services.NewResource(crmStub, storageStub)
	storageStub.BucketPolicyResponse = &iam.Policy{}
	conf := &services.Configuration{
		CloseBucket: &services.CloseBucket{
			Resources: &services.Resources{
				FolderIDs: folderIDs,
			},
		},
	}
	return &services.Global{Logger: log, Resource: res, Configuration: conf}, crmStub, storageStub
}
