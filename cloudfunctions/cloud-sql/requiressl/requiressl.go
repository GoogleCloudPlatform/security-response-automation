package requiressl

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

// Values contains the required values needed for this function.
type Values struct {
	ProjectID, InstanceName string
}

// Services contains the services needed for this function.
type Services struct {
	Configuration *services.Configuration
	CloudSQL      *services.CloudSQL
	Resource      *services.Resource
	Logger        *services.Logger
}

// ReadFinding will attempt to deserialize all supported findings for this function.
func ReadFinding(b []byte) (*Values, error) {
	var finding pb.SqlScanner
	r := &Values{}
	if err := json.Unmarshal(b, &finding); err != nil {
		return nil, errors.Wrap(services.ErrUnmarshal, err.Error())
	}
	switch finding.GetFinding().GetCategory() {
	case "SSL_NOT_ENFORCED":
		r.InstanceName = sha.Instance(finding.GetFinding().GetResourceName())
		r.ProjectID = finding.GetFinding().GetSourceProperties().GetProjectID()
	default:
		return nil, services.ErrUnsupportedFinding
	}
	if r.InstanceName == "" || r.ProjectID == "" {
		return nil, services.ErrValueNotFound
	}
	return r, nil
}

// Execute will remove any public ips in sql instance found within the provided folders.
func Execute(ctx context.Context, values *Values, services *Services) error {
	resources := services.Configuration.CloudSQLRequireSSL.Resources
	return services.Resource.IfProjectWithinResources(ctx, resources, values.ProjectID, func() error {
		if err := services.CloudSQL.RequireSSL(ctx, values.ProjectID, values.InstanceName); err != nil {
			return err
		}
		services.Logger.Info("enforced ssl on sql instance %q in project %q.", values.InstanceName, values.ProjectID)
		return nil
	})
}
