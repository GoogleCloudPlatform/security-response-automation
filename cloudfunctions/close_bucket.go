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
	"log"
	"strings"

	"github.com/googlecloudplatform/threat-automation/entities"
	"github.com/googlecloudplatform/threat-automation/providers/sha"
	"github.com/pkg/errors"

	"cloud.google.com/go/pubsub"
)

// resourcePrefix is the prefix before the bucket name in a SHA storage scanner finding.
const resourcePrefix = "//storage.googleapis.com/"

// publicUsers contains a slice of public users we want to remove.
var publicUsers = []string{"allUsers", "allAuthenticatedUsers"}

// CloseBucket will remove any public users from buckets found within the provided folders.
func CloseBucket(ctx context.Context, m pubsub.Message, r *entities.Resource, folderIDs []string, l *entities.Logger) error {
	f, err := sha.NewPublicBucket(&m)
	if err != nil {
		return errors.Wrap(err, "failed to read finding")
	}
	if f.Category() != "PUBLIC_BUCKET_ACL" {
		return errors.Errorf("not a supported finding: %q", f.Category())
	}

	bucketProject := f.ProjectID()
	bucketName := bucketName(f.Resource())

	log.Printf("removing public users from bucket %q in project %q", bucketName, bucketProject)

	log.Printf("listing project %q ancestors", bucketProject)
	ancestors, err := r.GetProjectAncestry(ctx, bucketProject)
	if err != nil {
		return errors.Wrap(err, "failed to get project ancestry")
	}

	log.Printf("ancestors returned from project %q: %v", bucketProject, ancestors)

	for _, resource := range ancestors {
		for _, folderID := range folderIDs {
			if resource != "folders/"+folderID {
				continue
			}
			l.Info("removing public members from bucket %q in project %q.", bucketName, bucketProject)
			if err = r.RemoveMembersFromBucket(ctx, bucketName, publicUsers); err != nil {
				return errors.Wrap(err, "failed to remove member from bucket")
			}
		}
	}
	return nil
}

// bucketName returns name of the bucket. Resource assumed valid due to prior validate call.
func bucketName(resource string) string {
	return strings.Split(resource, resourcePrefix)[1]
}
