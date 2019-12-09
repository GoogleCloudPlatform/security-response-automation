package services

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

// allIPs represents a IP network covering all valid IPv4 addresses.
const allIPs = "0.0.0.0/0"

// CloudSQLClient contains minimum interface required by the Cloud SQL service.
type CloudSQLClient interface {
	PatchInstance(context.Context, string, string, *sqladmin.DatabaseInstance) (*sqladmin.Operation, error)
	WaitSQL(string, *sqladmin.Operation) []error
	InstanceDetails(context.Context, string, string) (*sqladmin.DatabaseInstance, error)
	UpdateUser(context.Context, string, string, string, string, *sqladmin.User) (*sqladmin.Operation, error)
}

// CloudSQL service.
type CloudSQL struct {
	client CloudSQLClient
}

// NewCloudSQL returns a Cloud SQL service.
func NewCloudSQL(cc CloudSQLClient) *CloudSQL {
	return &CloudSQL{client: cc}
}

// RequireSSL modifies the configuration to require only SSL connections.
func (s *CloudSQL) RequireSSL(ctx context.Context, projectID string, instance string) error {
	op, err := s.client.PatchInstance(ctx, projectID, instance, &sqladmin.DatabaseInstance{
		Name:    instance,
		Project: projectID,
		Settings: &sqladmin.Settings{
			IpConfiguration: &sqladmin.IpConfiguration{
				RequireSsl: true,
			},
		},
	})
	if err != nil {
		return err
	}
	if err := s.wait(projectID, op); err != nil {
		return err
	}
	return nil
}

// UpdateUserPassword updates a user's password.
func (s *CloudSQL) UpdateUserPassword(ctx context.Context, projectID, instance, host, name, password string) error {
	op, err := s.client.UpdateUser(ctx, projectID, instance, host, name, &sqladmin.User{Password: password})
	if err != nil {
		return err
	}
	if err := s.wait(projectID, op); err != nil {
		return err
	}
	return nil
}

// InstanceDetails get details for an instance.
func (s *CloudSQL) InstanceDetails(ctx context.Context, projectID string, instance string) (*sqladmin.DatabaseInstance, error) {
	return s.client.InstanceDetails(ctx, projectID, instance)
}

// ClosePublicAccess removes all valid IPs the from the authorized networks for an instance.
func (s *CloudSQL) ClosePublicAccess(ctx context.Context, projectID, instance string, acls []*sqladmin.AclEntry) error {
	var authorizedNetworks []*sqladmin.AclEntry
	for _, ip := range acls {
		if ip.Value != allIPs {
			authorizedNetworks = append(authorizedNetworks, ip)
		}
	}

	// If there are no authorized networks the field must be explicitly declared as null.
	// Otherwise null fields are removed if not declared as such.
	var nullFields []string
	if len(authorizedNetworks) == 0 {
		nullFields = append(nullFields, "AuthorizedNetworks")
	}
	op, err := s.client.PatchInstance(ctx, projectID, instance, &sqladmin.DatabaseInstance{
		Name:    instance,
		Project: projectID,
		Settings: &sqladmin.Settings{
			IpConfiguration: &sqladmin.IpConfiguration{
				AuthorizedNetworks: authorizedNetworks,
				NullFields:         nullFields,
			},
		},
	})
	if err != nil {
		return err
	}
	if err := s.wait(projectID, op); err != nil {
		return err
	}
	return nil
}

// IsPublic checks if the Cloud SQL instance contains public IPs.
func (s *CloudSQL) IsPublic(acls []*sqladmin.AclEntry) bool {
	found := false
	for _, ip := range acls {
		if ip.Value == allIPs {
			found = true
			continue
		}
	}
	return found
}

func (s *CloudSQL) wait(project string, op *sqladmin.Operation) error {
	if errs := s.client.WaitSQL(project, op); len(errs) > 0 {
		return errs[0]
	}
	return nil
}
