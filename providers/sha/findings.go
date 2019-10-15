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

// baseFinding contains fields all SCC SHA findings should provide.
type baseFinding struct {
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

// Finding is a 'base' struct representing SCC SHA fields that all findings should satisfy.
type Finding struct {
	base *baseFinding
}

// NewFinding returns a new ShaFinding.
func NewFinding(m *pubsub.Message) (*Finding, error) {
	f := Finding{}

	if err := json.Unmarshal(m.Data, &f.base); err != nil {
		return nil, errors.Wrap(entities.ErrUnmarshal, err.Error())
	}

	if err := f.validate(); err != nil {
		return nil, err
	}

	return &f, nil
}

func (f *Finding) validate() error {

	if f.ResourceName() == "" {
		return errors.Wrap(entities.ErrValueNotFound, "does not have a resource name")
	}

	if f.Category() == "" {
		return errors.Wrap(entities.ErrValueNotFound, "does not have a category")
	}

	return nil

}

// ResourceName returns the finding ResourceName
func (f *Finding) ResourceName() string {
	return f.base.Finding.ResourceName
}

// Category returns the finding Category
func (f *Finding) Category() string {
	return f.base.Finding.Category
}

// ScannerName returns the Security Health Analytics finding ScannerName
func (f *Finding) ScannerName() string {
	return f.base.Finding.SourceProperties.ScannerName
}

// ProjectID returns the Security Health Analytics finding ProjectID
func (f *Finding) ProjectID() string {
	return f.base.Finding.SourceProperties.ProjectID
}

// ExternalURI returns the Security Health Analytics finding ExternalURI
func (f *Finding) ExternalURI() string {
	return f.base.Finding.ExternalURI
}
