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

	"cloud.google.com/go/pubsub"
	"github.com/googlecloudplatform/threat-automation/entities"
	"github.com/googlecloudplatform/threat-automation/providers/sha"
	"github.com/pkg/errors"
)

// TODO(tomfitzgerald): Temporarily solution.
const conf = "folders"

// publicUsers contains a slice of public users we want to remove.
var publicUsers = []string{"allUsers", "allAuthenticatedUsers"}

// CloseBucket will remove any public users from buckets found within the provided folders.
func CloseBucket(ctx context.Context, m pubsub.Message, res *entities.Resource, folderIDs []string, log *entities.Logger) error {
	finding, err := sha.NewStorageScanner(&m)
	if err != nil {
		return errors.Wrap(err, "failed to read finding")
	}

	switch conf {
	case "folders":
		if err := folders(ctx, log, finding, res, folderIDs); err != nil {
			return errors.Wrap(err, "folders failed")
		}
	case "projects":
		// TODO(tomfitzgerald): Support.
	case "organization":
		// TODO(tomfitzgerald): Support.
	case "labels":
		// TODO(tomfitzgerald): Support.
	case "securitymarks":
		// TODO(tomfitzgerald): Support.
	default:
		return fmt.Errorf("unsupported configuration")
	}
	return nil
}

func folders(ctx context.Context, log *entities.Logger, finding *sha.StorageScanner, res *entities.Resource, folderIDs []string) error {
	return ProjectWithinFolders(ctx, finding.ProjectID(), folderIDs, res, func() error {
		log.Info("removing public members from bucket %q in project %q.", finding.BucketName(), finding.ProjectID())
		return closeBucket(ctx, res, finding.BucketName())
	})
}

func closeBucket(ctx context.Context, r *entities.Resource, bucket string) error {
	return r.RemoveMembersFromBucket(ctx, bucket, publicUsers)
}
