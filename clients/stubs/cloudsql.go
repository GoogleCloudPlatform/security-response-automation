package stubs

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

	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

// ErrResourceNonExistent is an error throw if the entity was not found.
var ErrResourceNonExistent = fmt.Errorf("googleapi: Error 400: Invalid request: Invalid instance name in request body")

// SQLAdminStub provides a stub for the SQL Admin client.
type SQLAdminStub struct {
	SavedInstanceUpdated *sqladmin.DatabaseInstance
}

// WaitSQL waits globally.
func (s *SQLAdminStub) WaitSQL(project string, op *sqladmin.Operation) []error {
	return []error{}
}

// PatchInstance updates partialy a cloud sql instance.
func (s *SQLAdminStub) PatchInstance(ctx context.Context, projectID string, instance string, databaseInstance *sqladmin.DatabaseInstance) (*sqladmin.Operation, error) {
	s.SavedInstanceUpdated = databaseInstance
	if projectID == "nonexisting" || instance == "nonexisting" || databaseInstance.Name == "nonexisting" {
		return nil, ErrResourceNonExistent
	}

	return &sqladmin.Operation{}, nil
}

// GetInstanceDetails gets detail from a instance in a project
func (s *SQLAdminStub) GetInstanceDetails(ctx context.Context, projectID string, instance string) (*sqladmin.DatabaseInstance, error) {
	if projectID == "nonexisting" || instance == "nonexisting" {
		return nil, ErrResourceNonExistent
	}
	return &sqladmin.DatabaseInstance{
		Name:    instance,
		Project: projectID,
		Settings: &sqladmin.Settings{
			IpConfiguration: &sqladmin.IpConfiguration{
				AuthorizedNetworks: []*sqladmin.AclEntry{
					&sqladmin.AclEntry{
						Value: "0.0.0.0/0",
					},
					&sqladmin.AclEntry{
						Value: "1.0.0.0/0",
					},
				},
			},
		},
	}, nil
}
