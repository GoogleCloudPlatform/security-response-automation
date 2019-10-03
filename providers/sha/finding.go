// Package sha holds Security Health Analytics finding entities and functions
package sha

import (
	"encoding/json"

	"cloud.google.com/go/pubsub"
	"github.com/googlecloudplatform/threat-automation/entities"
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
	firewallScanner = "FIREWALL_SCANNER"
)

var (
	// ErrNoResourceName thrown when finding does not have a resource name
	ErrNoResourceName = errors.New("does not have a resource name")
	// ErrNoCategory thrown when finding does not have a category
	ErrNoCategory = errors.New("does not have a category")
	// ErrNoProjectID thrown when finding does not have a project id
	ErrNoProjectID = errors.New("does not have a project id")
)

// Attributes common attributes to all Security Command Center findings
type Attributes struct {
	Finding struct {
		Name          string
		Parent        string
		State         string
		ExternalURI   string
		EventTime     string
		CreateTime    string
		ResourceName  string
		Category      string
		SecurityMarks struct {
			Name  string
			Marks map[string]string
		}
	}
}

// CommonSourceProperties holds SCC source properties common to all SHA findings
type CommonSourceProperties struct {
	Finding struct {
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
	}
}

// Finding a Security Health Analytics finding
type Finding struct {
	a  Attributes
	sp CommonSourceProperties
}

// NewFinding returns a new ShaFinding.
func NewFinding() *Finding {
	return &Finding{}
}

// ReadFinding unmarshals a Security Health Analytics finding from PubSub
func (f *Finding) ReadFinding(m *pubsub.Message) error {
	if err := json.Unmarshal(m.Data, &f.a); err != nil {
		return errors.Wrap(entities.ErrUnmarshal, err.Error())
	}

	if err := json.Unmarshal(m.Data, &f.sp); err != nil {
		return errors.Wrap(entities.ErrUnmarshal, err.Error())
	}

	if f.a.Finding.ResourceName == "" {
		return ErrNoResourceName
	}

	if f.a.Finding.Category == "" {
		return ErrNoCategory
	}

	if f.sp.Finding.SourceProperties.ProjectID == "" {
		return ErrNoProjectID
	}

	return nil
}
