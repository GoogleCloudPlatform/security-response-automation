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
	"github.com/googlecloudplatform/threat-automation/clients"
	"testing"

	"github.com/googlecloudplatform/threat-automation/clients/stubs"
)

func TestSendEmail(t *testing.T) {
	tests := []struct {
		name             string
		from             string
		to               []string
		body             string
		subject          string
		expectedError    string
		expectedResponse *clients.EmailResponse
	}{
		{
			name:             "send email",
			from:             "google-project@ciandt.com",
			to:               []string{"dgralmeida@gmail.com"},
			body:             "Local test of send mail from golang!",
			subject:          "Test mail golang",
			expectedError:    "",
			expectedResponse: &clients.EmailResponse{StatusCode: 200},
		},
		{
			name:             "send email fails",
			from:             "google-project@ciandt.com",
			to:               []string{"dgralmeida@gmail.com"},
			body:             "Local test of send mail from golang!",
			subject:          "Test mail golang",
			expectedError:    "Error to send email. StatusCode:(205)",
			expectedResponse: &clients.EmailResponse{StatusCode: 205},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := NewEmail(&stubs.EmailStub{
				StubbedSend: tt.expectedResponse,
			})

			res, err := email.Send(tt.subject, tt.from, tt.body, tt.to)

			if err != nil && err.Error() != tt.expectedError {
				t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expectedError, err)
			}

			if want, got := tt.expectedResponse, res; got != nil && want.StatusCode != got.StatusCode {
				t.Errorf("wrong response %v, want %v)", got, want)
			}

		})
	}
}
