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
	PatchInstance(context.Context, string, string, *sqladmin.DatabaseInstance) (*sqladmin.Operation, error)
	WaitSQL(string, *sqladmin.Operation) []error
	InstanceDetails(context.Context, string, string) (*sqladmin.DatabaseInstance, error)
}

// CloudSQL entity.
type CloudSQL struct {
	client CloudSQLClient
}

// NewCloudSQL returns a commmand center entity.
func NewCloudSQL(cc CloudSQLClient) *CloudSQL {
	return &CloudSQL{client: cc}
}

// WaitSQL will wait for the SQL operation to complete.
func (s *CloudSQL) WaitSQL(project string, op *sqladmin.Operation) []error {
	return s.client.WaitSQL(project, op)
}

// EnforceSSLConnection enforces SSL Connection to a database.
func (s *CloudSQL) EnforceSSLConnection(ctx context.Context, projectID string, instance string, region string) (*sqladmin.Operation, error) {
	return s.client.PatchInstance(ctx, projectID, instance, &sqladmin.DatabaseInstance{
		Name:           instance,
		Project:        projectID,
		ConnectionName: projectID + ":" + region + ":" + instance,
		Settings: &sqladmin.Settings{
			IpConfiguration: &sqladmin.IpConfiguration{
				RequireSsl: true,
			},
		},
	})
}

// InstanceDetails get details for an instance
func (s *CloudSQL) InstanceDetails(ctx context.Context, projectID string, instance string) (*sqladmin.DatabaseInstance, error) {
	return s.client.InstanceDetails(ctx, projectID, instance)
}

// ClosePublicAccess removes "0.0.0.0/0" from authorized IPs of an instance
func (s *CloudSQL) ClosePublicAccess(ctx context.Context, projectID string, instance string, instanceDetails *sqladmin.DatabaseInstance) (*sqladmin.Operation, error) {
	var authorizedIps []*sqladmin.AclEntry
	for _, ip := range instanceDetails.Settings.IpConfiguration.AuthorizedNetworks {
		if ip.Value != "0.0.0.0/0" {
			authorizedIps = append(authorizedIps, ip)
		}
	}

	// null fields are removed by default, must explicitly declare as intend to be null so they are preserved.
	var nullFields []string
	if len(authorizedIps) == 0 {
		nullFields = append(nullFields, "AuthorizedNetworks")
	}

	return s.client.PatchInstance(ctx, projectID, instance, &sqladmin.DatabaseInstance{
		Name:    instance,
		Project: projectID,
		Settings: &sqladmin.Settings{
			IpConfiguration: &sqladmin.IpConfiguration{
				AuthorizedNetworks: authorizedIps,
				NullFields:         nullFields,
			},
		},
	})
}
