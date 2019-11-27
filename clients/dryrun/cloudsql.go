package dryrun

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

	"github.com/googlecloudplatform/security-response-automation/clients"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

// CloudSQL client.
type CloudSQL struct {
	sqlClient *clients.CloudSQL
}

// NewDryRunCloudSQL returns and initializes a Cloud SQL client.
func NewDryRunCloudSQL(original *clients.CloudSQL) (*CloudSQL, error) {
	return &CloudSQL{sqlClient: original}, nil
}

// UpdateUser updates a given user.
func (s *CloudSQL) UpdateUser(ctx context.Context, projectID, instance, host, name string, user *sqladmin.User) (*sqladmin.Operation, error) {
	log.Printf("dry_run on, would call 'UpdateUser' with params projectID: %q, instance: %q, host: %q, name: %q, user: %+v", projectID, instance, host, name, user)
	return &sqladmin.Operation{}, nil
}

// PatchInstance updates partialy a Cloud SQL instance.
func (s *CloudSQL) PatchInstance(ctx context.Context, projectID, instance string, databaseInstance *sqladmin.DatabaseInstance) (*sqladmin.Operation, error) {
	log.Printf("dry_run on, would call 'PatchInstance' with params projectID: %q, instance: %q, databaseInstance: %+v", projectID, instance, databaseInstance)
	return &sqladmin.Operation{}, nil
}

// InstanceDetails gets detail from a instance in a project
func (s *CloudSQL) InstanceDetails(ctx context.Context, projectID string, instance string) (*sqladmin.DatabaseInstance, error) {
	return s.sqlClient.InstanceDetails(ctx, projectID, instance)
}

// WaitSQL will wait for the global operation to complete.
func (s *CloudSQL) WaitSQL(projectID string, op *sqladmin.Operation) []error {
	return nil
}
