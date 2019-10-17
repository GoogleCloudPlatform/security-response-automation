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

	sql "google.golang.org/api/sqladmin/v1beta4"
)

// ErrResourceNonExistent is an error throw if the entity was not found.
var ErrResourceNonExistent = fmt.Errorf("the Cloud SQL instance does not exist")

// CloudSQL provides a stub for the SQL Admin client.
type CloudSQL struct {
	SavedInstanceUpdated    *sql.DatabaseInstance
	InstanceDetailsResponse *sql.DatabaseInstance
}

// WaitSQL waits globally.
func (s *CloudSQL) WaitSQL(project string, op *sql.Operation) []error {
	return []error{}
}

// PatchInstance updates partialy a cloud sql instance.
func (s *CloudSQL) PatchInstance(ctx context.Context, projectID, instance string, databaseInstance *sql.DatabaseInstance) (*sql.Operation, error) {
	if projectID == "not-found" {
		return nil, fmt.Errorf("not found")
	}
	s.SavedInstanceUpdated = databaseInstance
	return &sql.Operation{}, nil
}

// UpdateUser updates a given user.
func (s *CloudSQL) UpdateUser(ctx context.Context, projectID, instance, host, name string, user *sql.User) (*sql.Operation, error) {
	if projectID == "not-found" {
		return nil, fmt.Errorf("not found")
	}
	if user.Password == "" {
		return nil, fmt.Errorf("No password provided")
	}
	return &sql.Operation{}, nil

// InstanceDetails gets detail from a instance in a project.
func (s *CloudSQL) InstanceDetails(ctx context.Context, projectID string, instance string) (*sql.DatabaseInstance, error) {
	if s.InstanceDetailsResponse == nil {
		return s.InstanceDetailsResponse, ErrResourceNonExistent
	}

	return s.InstanceDetailsResponse, nil
}
