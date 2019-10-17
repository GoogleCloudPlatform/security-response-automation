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
	"fmt"

	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

// CloudSQLClient contains minimum interface required by the Cloud SQL entity.
type CloudSQLClient interface {
	PatchInstance(context.Context, string, string, *sqladmin.DatabaseInstance) (*sqladmin.Operation, error)
	WaitSQL(string, *sqladmin.Operation) []error
	InstanceDetails(context.Context, string, string) (*sqladmin.DatabaseInstance, error)
	UpdateUser(context.Context, string, string, string, string, *sqladmin.User) (*sqladmin.Operation, error)
}

// CloudSQL entity.
type CloudSQL struct {
	client CloudSQLClient
}

// NewCloudSQL returns a Cloud SQL entity.
func NewCloudSQL(cc CloudSQLClient) *CloudSQL {
	return &CloudSQL{client: cc}
}

// Wait will wait for the SQL operation to complete.
func (s *CloudSQL) Wait(project string, op *sqladmin.Operation) []error {
	return s.client.WaitSQL(project, op)
}

// RequireSSL modifies the configuration to require only SSL connections.
func (s *CloudSQL) RequireSSL(ctx context.Context, projectID string, instance string, region string) (*sqladmin.Operation, error) {
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

// UpdateUserPassword updates a user's password.
func (s *CloudSQL) UpdateUserPassword(ctx context.Context, projectID, instance, host, name, password string) (*sqladmin.Operation, error) {
	user := &sqladmin.User{
		Password: password,
	}
	return s.client.UpdateUser(ctx, projectID, instance, host, name, user)
}

// InstanceDetails get details for an instance
func (s *CloudSQL) InstanceDetails(ctx context.Context, projectID string, instance string) (*sqladmin.DatabaseInstance, error) {
	return s.client.InstanceDetails(ctx, projectID, instance)
}

// ClosePublicAccess removes "0.0.0.0/0" from authorized IPs of an instance
func (s *CloudSQL) ClosePublicAccess(ctx context.Context, projectID string, instance string, instanceDetails *sqladmin.DatabaseInstance) (*sqladmin.Operation, error) {

	if instanceDetails == nil {
		return nil, fmt.Errorf("the Cloud SQL instance does not exist")
	}

	var authorizedIps []*sqladmin.AclEntry
	found := false
	for _, ip := range instanceDetails.Settings.IpConfiguration.AuthorizedNetworks {
		if ip.Value == "0.0.0.0/0" {
			found = true
			continue
		}
		authorizedIps = append(authorizedIps, ip)

	}

	if !found {
		return nil, nil
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
