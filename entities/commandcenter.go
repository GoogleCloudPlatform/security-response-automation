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

	crm "google.golang.org/genproto/googleapis/cloud/securitycenter/v1beta1"
	"google.golang.org/genproto/protobuf/field_mask"
)

// CommandCenterClient contains minimum interface required by the command center entity.
type CommandCenterClient interface {
	AddSecurityMarks(context.Context, *crm.UpdateSecurityMarksRequest) (*crm.SecurityMarks, error)
}

// CommandCenter entity
type CommandCenter struct {
	c CommandCenterClient
}

// NewCommandCenter returns a commmand center entity.
func NewCommandCenter(cc CommandCenterClient) *CommandCenter {
	return &CommandCenter{c: cc}
}

// AddSecurityMarks to a finding or asset
func (r *CommandCenter) AddSecurityMarks(ctx context.Context, findingID string, securityMarks map[string]string) (*crm.SecurityMarks, error) {
	var paths []string
	for key := range securityMarks {
		paths = append(paths, "marks."+key)
	}

	request := &crm.UpdateSecurityMarksRequest{
		UpdateMask: &field_mask.FieldMask{
			Paths: paths,
		},
		SecurityMarks: &crm.SecurityMarks{
			Name: fmt.Sprintf("%s/securityMarks", findingID),
			// Note keys correspond to the last part of each path.
			Marks: securityMarks,
		},
	}
	resp, err := r.c.AddSecurityMarks(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to add security marks: %q", err)
	}

	return resp, nil
}
