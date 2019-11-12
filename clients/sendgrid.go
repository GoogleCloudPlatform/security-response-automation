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
	"fmt"

	"github.com/sendgrid/rest"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

const (
	// emailSender name used as sender.
	emailSender = "Security Response Automation"
)

// SendGridClient client provider -------------------------------------------------/
type SendGridClient interface {
	Send(mail *mail.SGMailV3) (*rest.Response, error)
}

// SendGrid client.
type SendGrid struct {
	Service SendGridClient
}

// NewSendGridClient returns and initializes the SendGrid client.
func NewSendGridClient(apiKey string) *SendGrid {
	return &SendGrid{Service: sendgrid.NewSendClient(apiKey)}
}

// Send email SendGrid.
func (s *SendGrid) Send(subject, from, body string, to []string) (*rest.Response, error) {
	e := createEmail(subject, from, body, emailSender, to)
	r, err := s.Service.Send(e)

	if err != nil {
		return nil, err
	}

	if r.StatusCode < 200 || r.StatusCode > 202 {
		return nil, fmt.Errorf("Error to send email. StatusCode:(%d)", r.StatusCode)
	}

	return r, err
}

func createEmail(subject, from, body, sender string, to []string) *mail.SGMailV3 {
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
