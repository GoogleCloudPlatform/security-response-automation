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
	"encoding/json"

	pb "github.com/googlecloudplatform/threat-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/threat-automation/entities"
	"github.com/googlecloudplatform/threat-automation/providers/sha"
	"github.com/pkg/errors"
)

// publicUsers contains a slice of public users we want to remove.
var publicUsers = []string{"allUsers", "allAuthenticatedUsers"}

// Required contains the required values needed for this function.
type Required struct {
	BucketName, ProjectID string
}

// ReadFinding will attempt to deserialize all supported findings for this function.
func ReadFinding(b []byte) (*Required, error) {
	var finding pb.StorageScanner
	r := &Required{}
	if err := json.Unmarshal(b, &finding); err != nil {
		return nil, errors.Wrap(entities.ErrUnmarshal, err.Error())
	}
	switch finding.GetFinding().GetCategory() {
	case "PUBLIC_BUCKET_ACL":
		r.BucketName = sha.BucketName(finding.GetFinding().GetResourceName())
		r.ProjectID = finding.GetFinding().GetSourceProperties().GetProjectId()
	}
	if r.BucketName == "" || r.ProjectID == "" {
		return nil, entities.ErrValueNotFound
	}
	return r, nil
}

// Execute will remove any public users from buckets found within the provided folders.
func Execute(ctx context.Context, required *Required, ent *entities.Entity) error {
	r := remove(ctx, required, ent.Logger, ent.Resource)
	if err := ent.Resource.IfProjectInFolders(ctx, ent.Configuration.CloseBucket.Resources.FolderIDs, required.ProjectID, r); err != nil {
		return errors.Wrap(err, "folders failed")
	}

	if err := ent.Resource.IfProjectInProjects(ctx, ent.Configuration.CloseBucket.Resources.ProjectIDs, required.ProjectID, r); err != nil {
		return errors.Wrap(err, "projects failed")
	}

	return nil
}

func remove(ctx context.Context, required *Required, log *entities.Logger, res *entities.Resource) func() error {
	return func() error {
		log.Info("removing public members from bucket %q in project %q.", required.BucketName, required.ProjectID)
		return res.RemoveMembersFromBucket(ctx, required.BucketName, publicUsers)
	}
}
