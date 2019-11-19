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
	"context"

	"github.com/PagerDuty/go-pagerduty"
)

// PagerDuty service.
type PagerDuty struct {
	client PagerDutyClient
}

// PagerDutyClient contains methods used by the PagerDuty service.
type PagerDutyClient interface {
	CreateIncident(from, serviceID, title, body string) (*pagerduty.Incident, error)
}

// NewPagerDuty returns a PagerDuty service.
func NewPagerDuty(cs PagerDutyClient) *PagerDuty {
	return &PagerDuty{client: cs}
}

// CreateIncident will create an incident within PagerDuty.
func (p *PagerDuty) CreateIncident(ctx context.Context, from, serviceID, title, body string) error {
	if _, err := p.client.CreateIncident(from, serviceID, title, body); err != nil {
		return err
	}
	return nil
}
