// Package stubs provides testable stubs for clients.
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
	"strings"

	sccpb "google.golang.org/genproto/googleapis/cloud/securitycenter/v1beta1"
)

// ErrEntityNonExistent is a stub error returned simulating an error in case of entity was not found.
var ErrEntityNonExistent = fmt.Errorf("rpc error: code = NotFound desc = Requested entity was not found")

// SecurityCommandCenterStub provides a stub for the Security Command center client..
type SecurityCommandCenterStub struct {
	GetUpdatedSecurityMarks *sccpb.SecurityMarks
	GetUpdatedFindings      *sccpb.Finding
}

// UpdateFinding updates a finding in SCC.
func (s *SecurityCommandCenterStub) UpdateFinding(ctx context.Context, request *sccpb.UpdateFindingRequest) (*sccpb.Finding, error) {
	return s.GetUpdatedFindings, nil
}

// AddSecurityMarks to a finding or asset.
func (s *SecurityCommandCenterStub) AddSecurityMarks(ctx context.Context, request *sccpb.UpdateSecurityMarksRequest) (*sccpb.SecurityMarks, error) {
	if strings.HasPrefix(request.SecurityMarks.GetName(), "nonexistent") {
		return nil, ErrEntityNonExistent
	}
	return s.GetUpdatedSecurityMarks, nil
}
