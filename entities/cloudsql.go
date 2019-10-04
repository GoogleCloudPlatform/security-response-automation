package entities

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

	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

// CloudSQLClient contains minimum interface required by the cloud sql entity.
type CloudSQLClient interface {
	EnforceSSLConection(context.Context, string, string, *sqladmin.DatabaseInstance) (*sqladmin.Operation, error)
	GetDataBaseInstance(context.Context, string, string, string) (*sqladmin.Database, error)
}

// CloudSQL entity.
type CloudSQL struct {
	client CloudSQLClient
}

// NewCloudSQL returns a commmand center entity.
func NewCloudSQL(cc CloudSQLClient) *CloudSQL {
	return &CloudSQL{client: cc}
}

// GetDataBaseInstance gets details from a database
func (s *CloudSQL) GetDataBaseInstance(ctx context.Context, project string, instance string, database string) (*sqladmin.Database, error) {
	return s.GetDataBaseInstance(ctx, project, instance, database)
}

// EnforceSSLConnection enforces SSL Connection to a database.
func (s *CloudSQL) EnforceSSLConnection(ctx context.Context, project string, instance string, database string, region string) (*sqladmin.Operation, error) {
	return s.client.EnforceSSLConection(ctx, project, instance, &sqladmin.DatabaseInstance{
		Name:           database,
		Project:        project,
		ConnectionName: project + ":" + region + ":" + instance,
		Settings: &sqladmin.Settings{
			IpConfiguration: &sqladmin.IpConfiguration{
				RequireSsl: true,
			},
		},
	})
}
