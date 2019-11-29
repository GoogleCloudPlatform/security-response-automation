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
	"bytes"
	"fmt"
	"html/template"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/sendgrid/rest"
)

const templatesPath = "templates/"

var (
	//errFindAbsPath finding absolute file path
	errFindAbsPath = errors.New("Error finding absolute file path")

	// errLoadTemplate error on load template file.
	errLoadTemplate = errors.New("Error on load template file")

	// errParseTemplate error on set the template content values.
	errParseTemplate = errors.New("Error on parse template")
)

// EmailClient is the interface used for sending emails.
type EmailClient interface {
	Send(subject, from, body string, to []string) (*rest.Response, error)
}

// EmailResponse contains the response from sending an email.
type EmailResponse struct {
	StatusCode int
	Body       string
}

// Email is the service used to send emails.
type Email struct {
	service EmailClient
	config  *Configuration
}

// NewEmail creates a new email service.
func NewEmail(service EmailClient, config *Configuration) *Email {
	return &Email{service: service, config: config}
}

// Send will send an email.
func (m *Email) Send(subject, from, body string, to []string) (*rest.Response, error) {
	return m.service.Send(subject, from, body, to)
}

// RenderTemplate parses the content based on template.
func (m *Email) RenderTemplate(templateName string, templateContent interface{}) (string, error) {
	fileName := filepath.Join(templatesPath, templateName)
	appPath, err := os.Getwd()
	filePath := filepath.Join(appPath, fileName)

	file, err := template.ParseGlob(filePath)
	if err != nil {
		return "", errors.Wrap(errLoadTemplate, err.Error())
	}

	out := &bytes.Buffer{}

	if err := file.Execute(out, templateContent); err != nil {
		return "", errors.Wrap(errParseTemplate, err.Error())
	}

	return out.String(), nil
}

// Notify sends email notification with AuditLogs information
func (n *Email) Notify(audit *AuditLog) error{
	if n.config.Email.Enabled{
		subject := "A security remediation was automatically done"
		var actions, status string
		for _, entry := range audit.events {
			status = "Remediation done successfully"
			if entry.isError{
				status = "Error trying to execute"
			}
			actions += fmt.Sprintf("%s - %s: %s \n", entry.date, status, entry.text)
		}
		content := struct{ Content mailContent }{Content: mailContent{Greeting: "Hello!", Finding: audit.finding, Actions: actions}}
		body, err := n.RenderTemplate( "email/journal.tmpl", content)
		if err != nil{
			return err
		}
		_, err = n.Send(subject, n.config.Email.From, body, n.config.Email.To)
		if err != nil{
			return err
		}
	}
	return nil
}