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
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/googlecloudplatform/security-response-automation/clients/stubs"

	crm "google.golang.org/genproto/googleapis/cloud/securitycenter/v1beta1"
	sccpb "google.golang.org/genproto/googleapis/cloud/securitycenter/v1beta1"
	"google.golang.org/genproto/protobuf/field_mask"
)

func TestAddSecurityMarkToFinding(t *testing.T) {
	tests := []struct {
		name             string
		securityMark     map[string]string
		serviceID        string
		expectedError    error
		expectedResponse *sccpb.SecurityMarks
		expectedRequest  *sccpb.UpdateSecurityMarksRequest
	}{

		{
			name:             "add Security Mark on a existent finding",
			securityMark:     map[string]string{"automationTest": "true"},
			serviceID:        "organizations/1055058813388/sources/2299436883026055247/findings/f909c48ed690424397eb3c3242062599",
			expectedError:    nil,
			expectedResponse: &sccpb.SecurityMarks{},
			expectedRequest: &sccpb.UpdateSecurityMarksRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"marks.automationTest"},
				},
				SecurityMarks: &crm.SecurityMarks{
					Name:  "organizations/1055058813388/sources/2299436883026055247/findings/f909c48ed690424397eb3c3242062599/securityMarks",
					Marks: map[string]string{"automationTest": "true"},
				},
			},
		},
		{
			name:             "add Security Mark on a nonexistent finding",
			securityMark:     map[string]string{"automationTestFailing": "true"},
			serviceID:        "nonexistent",
			expectedError:    stubs.ErrEntityNonExistent,
			expectedResponse: nil,
			expectedRequest: &sccpb.UpdateSecurityMarksRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"marks.automationTestFailing"},
				},
				SecurityMarks: &crm.SecurityMarks{
					Name:  "nonexistent/securityMarks",
					Marks: map[string]string{"automationTestFailing": "true"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			commandCenterStub := &stubs.SecurityCommandCenterStub{}
			ctx := context.Background()
			c := NewCommandCenter(commandCenterStub)
			r, err := c.AddSecurityMarks(ctx, tt.serviceID, tt.securityMark)
			cmpRequest := cmp.Comparer(func(x, y *sccpb.UpdateSecurityMarksRequest) bool {
				xb, err := json.Marshal(x)
				if err != nil {
					t.Fatal(err)
				}
				yb, err := json.Marshal(x)
				if err != nil {
					t.Fatal(err)
				}
				return (string(xb) == string(yb))
			})
			if diff := cmp.Diff(commandCenterStub.GetUpdateSecurityMarksRequest, tt.expectedRequest, cmpRequest); diff != "" {
				t.Errorf("%v failed, difference: %+v", tt.name, diff)
			}

			if tt.expectedError != nil && err != tt.expectedError {
				t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expectedError, err)
			}

			if tt.expectedError == nil && r == nil {
				t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expectedResponse, r)
			}
		})
	}
}
