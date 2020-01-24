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

	"github.com/googleapis/gax-go/v2"
	scc "github.com/googlecloudplatform/security-response-automation/clients/cscc/v1p1alpha1"
	"google.golang.org/genproto/protobuf/field_mask"
)

// CommandCenterClient contains minimum interface required by the command center service.
type CommandCenterClient interface {
	UpdateSecurityMarks(ctx context.Context, req *scc.UpdateSecurityMarksRequest, opts ...gax.CallOption) (*scc.SecurityMarks, error)
}

// CommandCenter service.
type CommandCenter struct {
	client CommandCenterClient
}

// NewCommandCenter returns a command center service.
func NewCommandCenter(cc CommandCenterClient) *CommandCenter {
	return &CommandCenter{client: cc}
}

// UpdateSecurityMarks in an Asset or Finding
func (r *CommandCenter) UpdateSecurityMarks(ctx context.Context, serviceID string, securityMarks map[string]string) (*scc.SecurityMarks, error) {
	var paths []string
	for k := range securityMarks {
		paths = append(paths, "marks."+k)
	}
	return r.client.UpdateSecurityMarks(ctx, &scc.UpdateSecurityMarksRequest{
		UpdateMask: &field_mask.FieldMask{
			Paths: paths,
		},
		SecurityMarks: &scc.SecurityMarks{
			Name:  serviceID + "/securityMarks",
			Marks: securityMarks,
		},
	})
}
