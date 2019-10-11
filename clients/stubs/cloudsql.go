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

// CloudSQL provides a stub for the Cloud SQL client.
type CloudSQL struct {
	SavedInstanceUpdated *sql.DatabaseInstance
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
