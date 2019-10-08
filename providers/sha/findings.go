// Package sha holds Security Health Analytics finding entities and functions
package sha

import (
	"encoding/json"

	"cloud.google.com/go/pubsub"
	"github.com/pkg/errors"
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
	errorMsgFailedToUnmarshal  = "failed to unmarshal"
	errorMsgMissingResouceName = "does not have a resource name"
	errorMsgMissingCategory    = "does not have a category"
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
func NewFinding() *Finding {
	return &Finding{}
}

// ReadFinding unmarshals a Security Health Analytics finding from PubSub
func (f *Finding) ReadFinding(m *pubsub.Message) error {
	if err := json.Unmarshal(m.Data, &f); err != nil {
		return errors.Wrap(err, errorMsgFailedToUnmarshal)
	}

	if f.Finding.ResourceName == "" {
		return errors.New(errorMsgMissingResouceName)
	}

	if f.Finding.Category == "" {
		return errors.New(errorMsgMissingCategory)
	}

	return nil
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
