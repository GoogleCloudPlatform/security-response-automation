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

	pb "github.com/googlecloudplatform/security-response-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/sha"
	"github.com/googlecloudplatform/security-response-automation/services"
	"github.com/pkg/errors"
)

// publicUsers contains a slice of public users we want to remove.
var publicUsers = []string{"allUsers", "allAuthenticatedUsers"}

// Values contains the required values needed for this function.
type Values struct {
	BucketName, ProjectID string
}

// Services contains the services needed for this function.
type Services struct {
	Configuration *services.Configuration
	Resource      *services.Resource
	Logger        *services.Logger
}

// ReadFinding will attempt to deserialize all supported findings for this function.
func ReadFinding(b []byte) (*Values, error) {
	var finding pb.StorageScanner
	r := &Values{}
	if err := json.Unmarshal(b, &finding); err != nil {
		return nil, errors.Wrap(services.ErrUnmarshal, err.Error())
	}
	if finding.GetFinding().GetState() != "ACTIVE" {
		return nil, services.ErrInactiveFinding
	}
	switch finding.GetFinding().GetCategory() {
	case "PUBLIC_BUCKET_ACL":
		r.BucketName = sha.BucketName(finding.GetFinding().GetResourceName())
		r.ProjectID = finding.GetFinding().GetSourceProperties().GetProjectId()
	default:
		return nil, services.ErrUnsupportedFinding
	}
	if r.BucketName == "" || r.ProjectID == "" {
		return nil, services.ErrValueNotFound
	}
	return r, nil
}

// Execute will remove any public users from buckets found within the provided folders.
func Execute(ctx context.Context, values *Values, services *Services) error {
	resources := services.Configuration.CloseBucket.Resources
	return services.Resource.IfProjectWithinResources(ctx, resources, values.ProjectID, func() error {
		if err := services.Resource.RemoveMembersFromBucket(ctx, values.BucketName, publicUsers); err != nil {
			return err
		}
		services.Logger.Info("removed public members from bucket %q in project %q", values.BucketName, values.ProjectID)
		return nil
	})
}
