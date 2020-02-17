package sendgrid

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
	"context"
	"log"

	"github.com/googlecloudplatform/security-response-automation/services"
)

// Services contains the services needed for this function.
type Services struct {
	Email  *services.Email
	Logger *services.Logger
}

// Values contains the required values needed for this function.
type Values struct {
	Subject         string
	From            string
	To              []string
	APIKey          string          `yaml:"api_key"`
	TemplatePath    string          `yaml:"template_path"`
	TemplateContent TemplateContent `yaml:"template_content"`
}

// TemplateContent contains values for rendering templates for e-mail
type TemplateContent struct {
	Message string
}

// Execute will send emails using Sendgrid.
func Execute(ctx context.Context, values *Values, services *Services) error {

	log.Printf("rendering template %q", values.TemplatePath)
	body, err := services.Email.RenderTemplate(values.TemplatePath, values.TemplateContent)
	if err != nil {
		services.Logger.Error("Error rendering template, %q", err)
		return err
	}

	log.Printf("sending email to %q", values.To)
	_, err = services.Email.Send(values.Subject, values.From, body, values.To)

	if err != nil {
		services.Logger.Error("Error sending e-mail, %q", err)
		return err
	}
	return nil
}
