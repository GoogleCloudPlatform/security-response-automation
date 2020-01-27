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

	"github.com/googleapis/gax-go/v2"
	scc "google.golang.org/genproto/googleapis/cloud/securitycenter/v1beta1"
)

// ErrEntityNonExistent is an error throw if the entity was not found.
var ErrEntityNonExistent = fmt.Errorf("rpc error: code = NotFound desc = Requested entity was not found")

// SecurityCommandCenterStub provides a stub for the Security Command center client.
type SecurityCommandCenterStub struct {
	GetUpdateSecurityMarksRequest *scc.UpdateSecurityMarksRequest
}

// UpdateSecurityMarks in an Asset or Finding
func (s *SecurityCommandCenterStub) UpdateSecurityMarks(ctx context.Context, req *scc.UpdateSecurityMarksRequest, opts ...gax.CallOption) (*scc.SecurityMarks, error) {
	s.GetUpdateSecurityMarksRequest = req
	if req.SecurityMarks.GetName() == "nonexistent/securityMarks" {
		return nil, ErrEntityNonExistent
	}
	return &scc.SecurityMarks{}, nil
}
