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

	sccpb "google.golang.org/genproto/googleapis/cloud/securitycenter/v1beta1"
)

// SecurityCommandCenterStub provides a stub for the CRM client..
type SecurityCommandCenterStub struct {
	GetUpdatedSecurityMarks *sccpb.SecurityMarks
}

// AddSecurityMarks to a finding or asset
func (s *SecurityCommandCenterStub) AddSecurityMarks(ctx context.Context, request *sccpb.UpdateSecurityMarksRequest) (*sccpb.SecurityMarks, error) {
	return s.GetUpdatedSecurityMarks, nil
}
