package pagerduty

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
	"github.com/googlecloudplatform/security-response-automation/services"
)

// Services contains the services needed for this function.
type Services struct {
	PagerDuty *services.PagerDuty
	Logger    *services.Logger
}

// Values contains the required values needed for this function.
type Values struct {
	APIKey    string `yaml:"api_key"`
	FromEmail string `yaml:"from_email"`
	ServiceID string `yaml:"service_id"`
	Title     string `yaml:"title"`
	Body      string
	DryRun    bool
}

// Execute will create an incident on PagerDuty.
func Execute(ctx context.Context, values *Values, services *Services) error {
	if values.DryRun {
		services.Logger.Info("dry run, would have created incident on PagerDuty. fromEmail: %q, serviceID: %q, title: %q", values.FromEmail, values.ServiceID, values.Title)
		return nil
	}
	services.Logger.Info("creating incident on PagerDuty. fromEmail: %q, serviceID: %q, title: %q", values.FromEmail, values.ServiceID, values.Title)
	if err := services.PagerDuty.CreateIncident(ctx, values.FromEmail, values.ServiceID, values.Title, values.Body); err != nil {
		return err
	}
	return nil
}
