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
	"testing"

	"github.com/googlecloudplatform/threat-automation/clients/stubs"

	sccpb "google.golang.org/genproto/googleapis/cloud/securitycenter/v1beta1"
)

func TestAddSecurityMarkToFinding(t *testing.T) {
	tests := []struct {
		name             string
		securityMark     map[string]string
		entityID         string
		expectedError    error
		expectedResponse *sccpb.SecurityMarks
	}{

		{
			name:             "add Security Mark on a existent finding",
			securityMark:     map[string]string{"automationTest": "true"},
			entityID:         "organizations/1055058813388/sources/2299436883026055247/findings/f909c48ed690424397eb3c3242062599",
			expectedError:    nil,
			expectedResponse: &sccpb.SecurityMarks{},
		},
		{
			name:             "add Security Mark on a nonexistent finding",
			securityMark:     map[string]string{"automationTest": "true"},
			entityID:         "nonexistent",
			expectedError:    stubs.ErrEntityNonExistent,
			expectedResponse: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			commandCenterStub := &stubs.SecurityCommandCenterStub{}
			ctx := context.Background()
			c := NewCommandCenter(commandCenterStub)
			_, err := c.AddSecurityMarks(ctx, tt.entityID, tt.securityMark)

			if commandCenterStub.GetUpdateSecurityMarksRequest.SecurityMarks.GetName() != tt.entityID+"/securityMarks" {
				t.Errorf("%v failed exp:%v got:%v", tt.name, tt.entityID+"/securityMarks", commandCenterStub.GetUpdateSecurityMarksRequest.SecurityMarks.GetName())
			}

			if commandCenterStub.GetUpdateSecurityMarksRequest.SecurityMarks.GetMarks()["automationTest"] != tt.securityMark["automationTest"] {
				t.Errorf("%v failed exp:%v got:%v", tt.name, tt.securityMark["automationTest"], commandCenterStub.GetUpdateSecurityMarksRequest.SecurityMarks.GetMarks()["automationTest"])
			}

			if commandCenterStub.GetUpdateSecurityMarksRequest.UpdateMask.GetPaths()[0] != "marks.automationTest" {
				t.Errorf("%v failed exp:%v got:%v", tt.name, "marks.automationTest", commandCenterStub.GetUpdateSecurityMarksRequest.UpdateMask.GetPaths()[0])
			}

			if tt.expectedError != nil && err != tt.expectedError {
				t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expectedError, err)
			}

			if tt.expectedError == nil && tt.expectedResponse == nil {
				t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expectedResponse, commandCenterStub.GetUpdatedSecurityMarks)
			}
		})
	}
}
