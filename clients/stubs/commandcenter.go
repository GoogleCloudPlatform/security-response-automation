package stubs

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

	sccpb "google.golang.org/genproto/googleapis/cloud/securitycenter/v1beta1"
)

// ErrEntityNonExistent is an error throw if the entity was not found.
var ErrEntityNonExistent = fmt.Errorf("rpc error: code = NotFound desc = Requested entity was not found")

// SecurityCommandCenterStub provides a stub for the Security Command center client.
type SecurityCommandCenterStub struct {
	GetUpdateSecurityMarksRequest *sccpb.UpdateSecurityMarksRequest
}

// AddSecurityMarks adds Security Marks to a finding or asset.
func (s *SecurityCommandCenterStub) AddSecurityMarks(ctx context.Context, request *sccpb.UpdateSecurityMarksRequest) (*sccpb.SecurityMarks, error) {
	s.GetUpdateSecurityMarksRequest = request
	if request.SecurityMarks.GetName() == "nonexistent/securityMarks" {
		return nil, ErrEntityNonExistent
	}
	return &sccpb.SecurityMarks{}, nil
}

// SetFindingState sets finding state
func (s *SecurityCommandCenterStub) SetFindingState(ctx context.Context, request *sccpb.SetFindingStateRequest) (*sccpb.Finding, error) {
	return &sccpb.Finding{}, nil
}
