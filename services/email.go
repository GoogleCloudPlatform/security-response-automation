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
	"html/template"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/sendgrid/rest"
)

const templatesPath = "../templates/"

var (
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
}

// NewEmail creates a new email service.
func NewEmail(service EmailClient) *Email {
	return &Email{service: service}
}

// Send will send an email.
func (m *Email) Send(subject, from, body string, to []string) (*rest.Response, error) {
	return m.service.Send(subject, from, body, to)
}

// RenderTemplate parses the content based on template.
func (m *Email) RenderTemplate(templateName string, templateContent interface{}) (string, error) {
	fileName := filepath.Join(templatesPath, templateName)
	file, err := template.ParseGlob(fileName)

	if err != nil {
		return "", errors.Wrap(errLoadTemplate, err.Error())
	}

	out := &bytes.Buffer{}

	if err := file.Execute(out, templateContent); err != nil {
		return "", errors.Wrap(errParseTemplate, err.Error())
	}

	return out.String(), nil
}
