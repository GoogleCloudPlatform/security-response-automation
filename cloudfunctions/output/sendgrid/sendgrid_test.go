package sendgrid

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

	"github.com/googlecloudplatform/security-response-automation/clients"
	"github.com/googlecloudplatform/security-response-automation/clients/stubs"
	"github.com/googlecloudplatform/security-response-automation/services"
	"github.com/sendgrid/rest"
)

func TestSendgrid(t *testing.T) {

	crmStub := &stubs.ResourceManagerStub{}
	ancestryResponse := services.CreateAncestors([]string{"project/test-project", "folder/123", "organization/456"})
	crmStub.GetAncestryResponse = ancestryResponse

	tests := []struct {
		name             string
		expectedError    string
		expectedResponse *rest.Response
		message          string
	}{
		{
			name:             "send email sendgrid client success",
			expectedError:    "",
			expectedResponse: &rest.Response{StatusCode: 200},
			message:          "Automation xpto was successfully done",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			ctx := context.Background()

			sendGrid := clients.NewSendGridClient("api-key")
			sendGrid.Service = &stubs.SendGridStub{
				StubbedSendErr: nil,
				StubbedSend: &rest.Response {
					StatusCode: 200,
				},
			}

			t.Run(tt.name, func(t *testing.T) {
				if err := Execute(ctx, &Values{
					Subject:         "Test",
					From:            "automation@organization.com",
					To:              []string {"test@organization.com"},
					APIKey:          "api-key",
					TemplatePath:    "../../../templates/successfull_remediation.tmpl",
					TemplateContent: TemplateContent{Message:tt.message},
				}, &Services{Email: services.NewEmail(sendGrid), Logger: services.NewLogger(&stubs.LoggerStub{})}); err != nil {
					t.Errorf("%q failed: %q", tt.name, err)
				}
			})

		})
	}
}