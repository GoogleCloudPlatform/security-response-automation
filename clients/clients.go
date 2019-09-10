/*
Package clients provides the required clients for taking automated actions.

Copyright 2019 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package clients

import (
	"context"

	scc "cloud.google.com/go/securitycenter/apiv1beta1"
	stg "cloud.google.com/go/storage"
	crm "google.golang.org/api/cloudresourcemanager/v1"
	cs "google.golang.org/api/compute/v1"
)

const (
	authFile = "credentials/auth.json"
)

// Clients is the minimum interface required for the provided clients.
type Clients interface {
	CloudResourceManager
	SecurityCommandCenter
	ComputeService
	Storage
	OperationsService
	SnapshotsService
}

// Client holds various clients used by libraries.
type Client struct {
	ctx       context.Context
	crm       *crm.Service
	scc       *scc.Client
	cs        *cs.Service
	stg       *stg.Client
	opsZone   *cs.ZoneOperationsService
	opsGlobal *cs.GlobalOperationsService
	sss       *cs.SnapshotsService
}

// New returns a new instance of a client.
func New() *Client {
	return &Client{}
}

// Initialize connects clients.
func (c *Client) Initialize() error {
	c.ctx = context.Background()

	if err := InstantiateStorage(c); err != nil {
		return err
	}

	if err := InstantiateCRM(c); err != nil {
		return err
	}

	if err := InstantiateSCC(c); err != nil {
		return err
	}

	if err := InstantiateCompute(c); err != nil {
		return err
	}

	InstantiateOperations(c)
	InstantiateSnapshots(c)

	return nil
}
