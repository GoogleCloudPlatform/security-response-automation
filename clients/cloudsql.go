package clients

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
	"log"
	"time"

	"google.golang.org/api/option"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

// SQLAdmin client.
type SQLAdmin struct {
	service    *sqladmin.Service
	opsService *sqladmin.OperationsService
}

// NewSQLAdmin returns and initializes a SQL Admin client.
func NewSQLAdmin(ctx context.Context, authFile string) (*SQLAdmin, error) {
	sql, err := sqladmin.NewService(ctx, option.WithCredentialsFile(authFile))
	if err != nil {
		return nil, fmt.Errorf("failed to init scc: %q", err)
	}
	return &SQLAdmin{
		service:    sql,
		opsService: sqladmin.NewOperationsService(sql),
	}, nil
}

// PatchInstance updates partialy a cloud sql instance.
func (s *SQLAdmin) PatchInstance(ctx context.Context, projectID string, instance string, databaseInstance *sqladmin.DatabaseInstance) (*sqladmin.Operation, error) {
	return s.service.Instances.Patch(projectID, instance, databaseInstance).Do()
}

// GetInstanceDetails gets detail from a instance in a project
func (s *SQLAdmin) GetInstanceDetails(ctx context.Context, projectID string, instance string) (*sqladmin.DatabaseInstance, error) {
	return s.service.Instances.Get(projectID, instance).Do()
}

// WaitSQL will wait for the global operation to complete.
func (s *SQLAdmin) WaitSQL(projectID string, op *sqladmin.Operation) []error {
	return waitSQL(op, func() (*sqladmin.Operation, error) {
		return s.opsService.Get(projectID, op.Name).Do()
	})
}

func waitSQL(op *sqladmin.Operation, fn func() (*sqladmin.Operation, error)) []error {
	if op.Error != nil {
		return returnSQLErrorCodes(op.Error.Errors)
	}
	for i := 0; i < maxLoops; i++ {
		o, err := fn()
		if err != nil {
			return []error{err}
		}
		if o.Error != nil {
			return returnSQLErrorCodes(o.Error.Errors)
		}
		if o.Status == "DONE" {
			return nil
		}
		if i%4 == 0 {
			log.Println("Waiting")
		}
		time.Sleep(loopSleep)
	}
	return []error{fmt.Errorf("operation timed out: %q", op.Name)}
}

func returnSQLErrorCodes(errors []*sqladmin.OperationError) []error {
	out := []error{}
	for _, err := range errors {
		out = append(out, fmt.Errorf("fail: %q", err.Code))
	}
	return out
}
