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
	"log"

	"github.com/sendgrid/rest"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

// NewSendGridClient creatre new send grid client
func NewSendGridClient(apiKey string) *sendgrid.Client {
	return sendgrid.NewSendClient(apiKey)
}

// SendGridSendClient struct to use sendgrid client
type SendGridSendClient interface {
	Send(email *mail.SGMailV3) (*rest.Response, error)
}

// EmailClient struct to use sendgrid client
type EmailClient struct {
	services SendGridSendClient
}

// NewEmailClient create new email client
func NewEmailClient(service SendGridSendClient) *EmailClient {
	return &EmailClient{
		services: service,
	}
}

// Send main action function
func (m *EmailClient) Send(subject, from, body string, tos []string) (*rest.Response, error) {
	email := m.Create(subject, from, body, tos)
	res, err := m.services.Send(email)

	if err != nil || res.StatusCode < 200 || res.StatusCode > 202 {
		return nil, fmt.Errorf("Error to send email. StatusCode: %d", res.StatusCode)
	}

	log.Printf("Email(s) sent successfully. StatusCode:(%d)", res.StatusCode)
	return res, nil
}

// Create email
func (m *EmailClient) Create(subject, from, body string, tos []string) *mail.SGMailV3 {
	email := mail.NewV3Mail()

	// TODO fill email name
	email.SetFrom(mail.NewEmail("", from))
	email.Subject = subject

	p := mail.NewPersonalization()
	for _, e := range tos {

		// TODO fill email name
		p.AddTos(mail.NewEmail("", e))
	}
	email.AddContent(mail.NewContent("text/plain", body))
	email.AddPersonalizations(p)
	return email
}
