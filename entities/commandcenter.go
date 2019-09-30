package entities

import (
	"context"
	"fmt"

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

	crm "google.golang.org/genproto/googleapis/cloud/securitycenter/v1beta1"
)

// CommandCenterClient contains minimum interface required by the command center entity.
type CommandCenterClient interface {
	AddSecurityMarks(context.Context, string) (*crm.SecurityMarks, error)
}

// CommandCenter entity
type CommandCenter struct {
	c CommandCenterClient
}

// AddSecurityMarks to a finding or asset
func (r *CommandCenter) AddSecurityMarks(ctx context.Context, request string) (*crm.SecurityMarks, error) {
	resp, err := r.c.AddSecurityMarks(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to add security marks: %q", err)
	}

	return resp, nil
}
