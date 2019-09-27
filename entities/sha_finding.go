// Package entities holds commonly used methods used in security automation.
package entities

import (
	"encoding/json"
	"errors"
	"fmt"

	"cloud.google.com/go/pubsub"
)

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

const (
	firewallScanner = "FIREWALL_SCANNER"
)

var (
	// ErrShaUnmarshal thrown when unable to unmarshal.
	ErrShaUnmarshal = errors.New("failed to unmarshal")
	// ErrNoResourceName thrown when finding does not have a resource name
	ErrNoResourceName = errors.New("does not have a resource name")
	// ErrNotFirewall thrown when ShaFinding is not a FIREWALL_SCANNER
	ErrNotFirewall = errors.New("not a FIREWALL_SCANNER Finding")
	// ErrNoProjectID thrown when finding does not have a project id
	ErrNoProjectID = errors.New("does not have a project id")
	// ErrUnknownRule thrown when the rule is unknown
	ErrUnknownRule         = errors.New("Unknown firewall category")
	supportedFirewallRules = map[string]bool{"OPEN_SSH_PORT": true, "OPEN_RDP_PORT": true, "OPEN_FIREWALL": true}
)

type sccFinding struct {
	Finding struct {
		ResourceName     string `json:"resourceName"`
		Category         string `json:"category"`
		SourceProperties struct {
			ScannerName string `json:"ScannerName"`
			ProjectID   string `json:"ProjectId"`
		}
	}
}

// ShaFinding a Security Health Analytics finding
type ShaFinding struct {
	finding sccFinding
}

// NewShaFinding returns a new ShaFinding.
func NewShaFinding() *ShaFinding {
	return &ShaFinding{}
}

// ReadShaFinding unmarshals a Security Health Analytics finding from PubSub
func (f *ShaFinding) ReadShaFinding(m *pubsub.Message) error {
	if err := json.Unmarshal(m.Data, &f.finding); err != nil {
		return ErrShaUnmarshal
	}

	if f.finding.Finding.ResourceName == "" {
		return ErrNoResourceName
	}

	if f.finding.Finding.SourceProperties.ScannerName != firewallScanner {
		return ErrNotFirewall
	}

	if !supportedFirewallRules[f.finding.Finding.Category] {
		fmt.Println(f.finding.Finding.Category)
		return ErrUnknownRule
	}

	if f.finding.Finding.SourceProperties.ProjectID == "" {
		return ErrNoProjectID
	}
	return nil
}

// ProjectID returns the Security Health Analytics finding ProjectID
func (f *ShaFinding) ProjectID() string {
	return f.finding.Finding.SourceProperties.ProjectID
}

// ResourceName returns the finding ResourceName
func (f *ShaFinding) ResourceName() string {
	return f.finding.Finding.ResourceName
}

// ScannerName returns the Security Health Analytics finding ScannerName
func (f *ShaFinding) ScannerName() string {
	return f.finding.Finding.SourceProperties.ScannerName
}

// Category returns the finding Category
func (f *ShaFinding) Category() string {
	return f.finding.Finding.Category
}
