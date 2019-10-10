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
	"fmt"

	"github.com/sendgrid/rest"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

const (
	sender = "Security Response Automation"
)

// EmailClient is the interface used for sending emails.
type EmailClient interface {
	Send(email *mail.SGMailV3) (*rest.Response, error)
}

// Email is the entity used to send emails.
type Email struct {
	service EmailClient
}

// NewEmail creates new email entity.
func NewEmail(service EmailClient) *Email {
	return &Email{service: service}
}

// NewSendGridClient creates new sendgrid client.
func NewSendGridClient(apiKey string) *sendgrid.Client {
	return sendgrid.NewSendClient(apiKey)
}

// Send will send an email.
func (m *Email) Send(subject, from, body string, to []string) (*rest.Response, error) {
	email := m.CreateEmail(subject, from, body, to)
	res, err := m.service.Send(email)

	if err != nil {
		return nil, err
	}

	if res.StatusCode < 200 || res.StatusCode > 202 {
		return nil, fmt.Errorf("Error to send email. StatusCode:(%d)", res.StatusCode)
	}
	return res, nil
}

// CreateEmail an sendgrid email.
func (m *Email) CreateEmail(subject, from, body string, to []string) *mail.SGMailV3 {
	email := mail.NewV3Mail()
	email.SetFrom(mail.NewEmail(sender, from))
	email.Subject = subject

	p := mail.NewPersonalization()
	for _, e := range to {
		p.AddTos(mail.NewEmail(e, e))
	}
	email.AddContent(mail.NewContent("text/plain", body))
	email.AddPersonalizations(p)
	return email
}
