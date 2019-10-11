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

	"cloud.google.com/go/pubsub"
	"github.com/googlecloudplatform/threat-automation/entities"
	"github.com/googlecloudplatform/threat-automation/providers/sha"
	"github.com/pkg/errors"
)

var (
	// publicUsers contains a slice of public users we want to remove.
	publicUsers = []string{"allUsers", "allAuthenticatedUsers"}
	// supportedCategory contains the SHA categories supported.
	supportedCategory = map[string]bool{
		"PUBLIC_BUCKET_ACL": true,
	}
)

// CloseBucket will remove any public users from buckets found within the provided folders.
func CloseBucket(ctx context.Context, m pubsub.Message, res *entities.Resource, log *entities.Logger, conf *Configuration) error {
	finding, err := sha.NewStorageScanner(&m)
	if err != nil {
		return errors.Wrap(err, "failed to read finding")
	}
	if !supportedCategory[finding.Category()] {
		return nil
	}

	if err := conf.IfProjectInFolders(ctx, finding.ProjectID(), remove(ctx, finding, log, res)); err != nil {
		return errors.Wrap(err, "folders failed")
	}

	if err := conf.IfProjectInProjects(ctx, finding.ProjectID(), remove(ctx, finding, log, res)); err != nil {
		return errors.Wrap(err, "projects failed")
	}

	return nil
}

func remove(ctx context.Context, finding *sha.StorageScanner, log *entities.Logger, res *entities.Resource) func() error {
	return func() error {
		log.Info("removing public members from bucket %q in project %q.", finding.BucketName(), finding.ProjectID())
		return res.RemoveMembersFromBucket(ctx, finding.BucketName(), publicUsers)
	}
}
