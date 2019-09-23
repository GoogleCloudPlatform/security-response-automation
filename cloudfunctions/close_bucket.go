package cloudfunctions

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
	"fmt"

	"github.com/googlecloudplatform/threat-automation/entities"

	"cloud.google.com/go/pubsub"
)

var publicUsers = []string{"allUsers", "allAuthenticatedUsers"}

// CloseBucket will remove any public users from buckets found within the provided folders.
func CloseBucket(ctx context.Context, m pubsub.Message, r *entities.Resource, folderIDs []string) error {
	// TODO(tomfitzgerald): Read this from a SHA finding. Faking for now.
	bucketProject := "gke-test-inside"
	bucketName := "this-bucket-is-public-on-purpose"

	ancestors, err := r.GetProjectAncestry(ctx, bucketProject)
	if err != nil {
		return fmt.Errorf("failed to get project ancestry: %q", err)
	}

	for _, resource := range ancestors {
		for _, folderID := range folderIDs {
			if resource != "folders/"+folderID {
				continue
			}
			if err = r.RemoveMembersFromBucket(ctx, bucketName, publicUsers); err != nil {
				return fmt.Errorf("failed to remove member from bucket: %q", err)
			}
		}
	}
	return nil
}
