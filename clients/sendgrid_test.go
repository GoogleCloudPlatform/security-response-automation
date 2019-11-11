package clients

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
	"testing"

	"github.com/googlecloudplatform/security-response-automation/clients/stubs"
	"github.com/pkg/errors"
	"github.com/sendgrid/rest"
)

func TestClientSendGridSendEmail(t *testing.T) {
	tests := []struct {
		name             string
		expectedError    string
		expectedResponse *rest.Response
		mockService      *stubs.SendGridStub
	}{
		{
			name:             "send email sendgrid client success",
			expectedError:    "",
			expectedResponse: &rest.Response{StatusCode: 200},
			mockService:      &stubs.SendGridStub{StubbedSend: &rest.Response{StatusCode: 200}},
		},
		{
			name:             "send email sendgrid fails by StatusCode",
			expectedError:    "Error to send email. StatusCode:(205)",
			expectedResponse: &rest.Response{StatusCode: 205},
			mockService:      &stubs.SendGridStub{StubbedSend: &rest.Response{StatusCode: 205}},
		},
		{
			name:             "send email sendgrid client fails request",
			expectedError:    "error to send email",
			expectedResponse: nil,
			mockService:      &stubs.SendGridStub{StubbedSendErr: errors.New("error to send email")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			sendGrid := NewSendGridClient("api-key")
			sendGrid.Service = tt.mockService

			res, err := sendGrid.Send("subject", "from", "body", []string{"tt"})

			if err != nil && err.Error() != tt.expectedError {
				t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expectedError, err)
			}

			if res != nil && tt.expectedResponse.StatusCode != res.StatusCode {
				t.Errorf("%s failed exp:%q got:%q", tt.name, res.StatusCode, tt.expectedResponse.StatusCode)
			}
		})
	}
}
