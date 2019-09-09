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
	"fmt"

	scc "cloud.google.com/go/securitycenter/apiv1beta1"
	"google.golang.org/api/option"
	pb "google.golang.org/genproto/googleapis/cloud/securitycenter/v1beta1"
)

// SecurityCommandCenter is the interface used by SCC.
type SecurityCommandCenter interface {
	UpdateFinding(*pb.UpdateFindingRequest) (*pb.Finding, error)
}

// InstantiateSCC initializes the SCC client.
func InstantiateSCC(c *Client) error {
	scc, err := scc.NewClient(c.ctx, option.WithCredentialsFile(authFile))
	if err != nil {
		return fmt.Errorf("failed to init scc: %q", err)
	}
	c.scc = scc
	return nil
}

// UpdateFinding updates a finding in SCC.
func (c *Client) UpdateFinding(request *pb.UpdateFindingRequest) (*pb.Finding, error) {
	resp, err := c.scc.UpdateFinding(c.ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to update policy: %q", err)
	}
	return resp, nil
}
