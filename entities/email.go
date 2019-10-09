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
	"bytes"
	"fmt"
	"html/template"
	"log"
	"path/filepath"

	"github.com/sendgrid/rest"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

// EmailClientServices struct to use sendgrid client
type EmailClientServices interface {
	Send(email *mail.SGMailV3) (*rest.Response, error)
}

// EmailClient struct to use sendgrid client
type EmailClient struct {
	service EmailClientServices
}

//NewEmailClient creates new client
func NewEmailClient(apiKey string) *EmailClient {
	return &EmailClient{service: sendgrid.NewSendClient(apiKey)}
}

// Send main action function
func (m *EmailClient) Send(subject, from, body string, tos []string) (*rest.Response, error) {
	email := m.CreateEmail(subject, from, body, tos)
	res, err := m.service.Send(email)

	if err != nil || res.StatusCode < 200 || res.StatusCode > 202 {
		return nil, fmt.Errorf("Error to send email. StatusCode:(%d)", res.StatusCode)
	}

	log.Printf("Email(s) sent successfully. StatusCode:(%d)", res.StatusCode)
	return res, nil
}

// CreateEmail an sendgrid email
func (m *EmailClient) CreateEmail(subject, from, body string, tos []string) *mail.SGMailV3 {
	email := mail.NewV3Mail()
	email.SetFrom(mail.NewEmail(from, from))
	email.Subject = subject

	p := mail.NewPersonalization()
	for _, e := range tos {
		p.AddTos(mail.NewEmail(e, e))
	}
	email.AddContent(mail.NewContent("text/html", m.ParseTemplate(body)))
	email.AddPersonalizations(p)
	return email
}

// ParseTemplate parse template
func (m *EmailClient) ParseTemplate(body string) string {
	pattern := filepath.Join("../templates/", "temp*.tmpl")
	tmpl := template.Must(template.ParseGlob(pattern))
	b := struct{ Body string }{Body: body}
	out := &bytes.Buffer{}

	err := tmpl.Execute(out, b)
	if err != nil {
		log.Fatalf("template execution: %s", err)
	}

	return out.String()
}
