// Package sha holds Security Health Analytics finding entities and functions
package sha

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
	"encoding/json"

	"cloud.google.com/go/pubsub"
	"github.com/googlecloudplatform/threat-automation/entities"
	"github.com/pkg/errors"
)

// Finding common attributes, source properties and security marks
// to all Security Health Analytics Security Command Center findings
type Finding struct {
	NotificationConfigName string
	Finding                struct {
		Name             string
		Parent           string
		ResourceName     string
		State            string
		Category         string
		ExternalURI      string
		SourceProperties struct {
			ReactivationCount     float32
			ExceptionInstructions string
			SeverityLevel         string
			Recommendation        string
			ProjectID             string
			DeactivationReason    string
			AssetCreationTime     string
			ScannerName           string
			ScanRunID             string
			Explanation           string
		}
		SecurityMarks struct {
			Name  string
			Marks map[string]string
		}
		EventTime  string
		CreateTime string
	}
}

// NewFinding returns a new ShaFinding.
func NewFinding(m *pubsub.Message) (*Finding, error) {
	f := Finding{}

	if err := json.Unmarshal(m.Data, &f); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal")
	}
	if f.Finding.ResourceName == "" {
		return nil, errors.Wrap(entities.ErrValueNotFound, "does not have a resource name")
	}

	if f.Finding.Category == "" {
		return nil, errors.Wrap(entities.ErrValueNotFound, "does not have a category")
	}

	return &f, nil
}

// ResourceName returns the finding ResourceName
func (f *Finding) ResourceName() string {
	return f.Finding.ResourceName
}

// Category returns the finding Category
func (f *Finding) Category() string {
	return f.Finding.Category
}

// ScannerName returns the Security Health Analytics finding ScannerName
func (f *Finding) ScannerName() string {
	return f.Finding.SourceProperties.ScannerName
}

// ProjectID returns the Security Health Analytics finding ProjectID
func (f *Finding) ProjectID() string {
	return f.Finding.SourceProperties.ProjectID
}
