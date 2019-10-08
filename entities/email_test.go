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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/googlecloudplatform/threat-automation/clients/stubs"
	"github.com/pkg/errors"
	"github.com/sendgrid/rest"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

func TestSendEmail(t *testing.T) {
	tests := []struct {
		name             string
		from             string
		to               []string
		body             string
		subject          string
		client           *EmailClient
		expectedError    error
		expectedResponse *rest.Response
	}{
		{
			name:             "test send email",
			from:             "google-project@ciandt.com",
			to:               []string{"dgralmeida@gmail.com"},
			body:             "Local test of send mail from golang!",
			subject:          "Teste mail golang",
			client:           NewEmailClient(&stubs.EmailStub{StubbedSend: &rest.Response{StatusCode: 200}}),
			expectedError:    nil,
			expectedResponse: &rest.Response{},
		},
		{
			name:             "test send email fails",
			from:             "google-project@ciandt.com",
			to:               []string{"dgralmeida@gmail.com"},
			body:             "Local test of send mail from golang!",
			subject:          "Teste mail golang",
			client:           NewEmailClient(&stubs.EmailStub{StubbedSend: &rest.Response{StatusCode: 205}}),
			expectedError:    errors.New("Error to send email. StatusCode: 205"),
			expectedResponse: &rest.Response{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.client.Send(tt.subject, tt.from, tt.body, tt.to)

			if err != nil && err.Error() != tt.expectedError.Error() {
				t.Error("error to send email!")
			}
		})
	}
}

func TestCreateEmail(t *testing.T) {
	tests := []struct {
		name             string
		from             string
		to               []string
		body             string
		subject          string
		expectedResponse *mail.SGMailV3
		expectedError    error
	}{
		{
			name:          "test send email",
			from:          "google-project@ciandt.com",
			to:            []string{"dgralmeida@gmail.com"},
			body:          "Local test of send mail from golang!",
			subject:       "Teste mail golang",
			expectedError: nil,
			expectedResponse: &mail.SGMailV3{
				From: &mail.Email{
					Address: "google-project@ciandt.com",
					Name:    "",
				},
				Subject: "Teste mail golang",
				Content: []*mail.Content{
					&mail.Content{
						Value: "Local test of send mail from golang!",
						Type:  "text/plain",
					},
				},
				Personalizations: []*mail.Personalization{
					&mail.Personalization{
						To: []*mail.Email{
							&mail.Email{
								Address: "dgralmeida@gmail.com",
								Name:    ""},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewEmailClient(&stubs.EmailStub{})
			email := client.Create(tt.subject, tt.from, tt.body, tt.to)

			if diff := cmp.Diff(tt.expectedResponse, email, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("%v failed exp:%v got:%v \n\r%v", tt.name, tt.expectedResponse, email, diff)
			}
		})
	}
}
