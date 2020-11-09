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

	crm "google.golang.org/genproto/googleapis/cloud/securitycenter/v1beta1"
	"google.golang.org/genproto/protobuf/field_mask"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

// CommandCenterClient contains minimum interface required by the command center service.
type CommandCenterClient interface {
	AddSecurityMarks(context.Context, *crm.UpdateSecurityMarksRequest) (*crm.SecurityMarks, error)
	SetFindingState(ctx context.Context, request *crm.SetFindingStateRequest) (*crm.Finding, error)
}

// CommandCenter service.
type CommandCenter struct {
	client CommandCenterClient
}

// NewCommandCenter returns a commmand center service.
func NewCommandCenter(cc CommandCenterClient) *CommandCenter {
	return &CommandCenter{client: cc}
}

// AddSecurityMarks to a finding or asset.
func (r *CommandCenter) AddSecurityMarks(ctx context.Context, serviceID string, securityMarks map[string]string) (*crm.SecurityMarks, error) {
	var paths []string
	for k := range securityMarks {
		paths = append(paths, "marks."+k)
	}

	return r.client.AddSecurityMarks(ctx, &crm.UpdateSecurityMarksRequest{
		UpdateMask: &field_mask.FieldMask{
			Paths: paths,
		},
		SecurityMarks: &crm.SecurityMarks{
			Name:  serviceID + "/securityMarks",
			Marks: securityMarks,
		},
	})
}

// SetInactive sets a finding as inactive
func (r *CommandCenter) SetInactive(ctx context.Context, name string) (*crm.Finding, error) {
	return r.client.SetFindingState(ctx, &crm.SetFindingStateRequest{
		Name:      name,
		State:     crm.Finding_INACTIVE,
		StartTime: timestamppb.Now(),
	})
}
