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

import "github.com/googlecloudplatform/threat-automation/clients"

// Email is the entity used to send emails.
type Email struct {
	service clients.EmailClient
}

// NewEmail creates a new email entity.
func NewEmail(service clients.EmailClient) *Email {
	return &Email{service: service}
}

// Send will send an email.
func (m *Email) Send(subject, from, body string, to []string) (*clients.EmailResponse, error) {
	return m.service.Send(subject, from, body, to)
}
