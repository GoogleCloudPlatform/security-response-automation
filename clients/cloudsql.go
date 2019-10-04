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

	"google.golang.org/api/option"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

// SQLAdmin client.
type SQLAdmin struct {
	service *sqladmin.Service
}

// NewSQLAdmin returns and initializes a SQL Admin client.
func NewSQLAdmin(ctx context.Context, authFile string) (*SQLAdmin, error) {
	sql, err := sqladmin.NewService(ctx, option.WithCredentialsFile(authFile))
	if err != nil {
		return nil, fmt.Errorf("failed to init scc: %q", err)
	}
	return &SQLAdmin{service: sql}, nil
}

// EnforceSSLConection updates SSL required connection to true in a cloud sql instance.
func (s *SQLAdmin) EnforceSSLConection(ctx context.Context, project string, instance string, databaseInstance *sqladmin.DatabaseInstance) (*sqladmin.Operation, error) {
	databaseInstance.Settings.IpConfiguration.RequireSsl = true
	return s.service.Instances.Patch(project, instance, databaseInstance).Do()
}
