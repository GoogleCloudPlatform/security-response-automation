package etd

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/googlecloudplatform/threat-automation/entities"

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
	// FindingSuffix is the log name suffix used by Event Threat Detection's findings.
	FindingSuffix = "/logs/threatdetection.googleapis.com%2Fdetection"
)

var (
	// extractProject used to extract a project Number from an affected resource.
	extractProject = regexp.MustCompile(`/projects/(.*)$`)
	// extractResource used to extract a resource.
	extractResource = regexp.MustCompile(`/([^/]+?/[^/]+?)?$`)
	// extractInstance used to extract a instance.
	extractInstance = regexp.MustCompile(`/instances/(.*)$`)
)

// baseFinding contains fields all ETD findings should provide.
type baseFinding struct {
	JSONPayload struct {
		AffectedResources []struct {
			GCPResourceName string
		}
		DetectionCategory struct {
			SubRuleName string
			RuleName    string
		}
		Properties struct {
			ProjectID string `json:"project_id"`
		}
	}
}

// Finding is a 'base' struct representing ETD fields that all findings should satisfy.
type Finding struct {
	base *baseFinding
}

// NewFinding deserializes a basic ETD finding from StackDriver.
func NewFinding(m *pubsub.Message) (*Finding, error) {
	var sd entities.StackDriverLog
	f := &Finding{}
	if err := json.Unmarshal(m.Data, &sd); err != nil {
		return f, entities.ErrUnmarshal
	}

	if sd.LogName == "" {
		return f, errors.Wrap(entities.ErrParsing, "log name not found")
	}

	if !strings.HasSuffix(sd.LogName, FindingSuffix) {
		return f, errors.Wrap(entities.ErrParsing, "missing etd log name suffix")
	}

	if err := json.Unmarshal(m.Data, &f.base); err != nil {
		return f, errors.Wrap(entities.ErrUnmarshal, "failed to unmarshal etd finding")
	}
	if v := f.validate(); !v {
		return nil, errors.Wrap(entities.ErrValueNotFound, "fields did not validate")
	}
	return f, nil
}

// validate ensures the fields to be accessed by getter methods are valid.
func (f *Finding) validate() bool {
	// TODO: Implement this.
	return true
}

// RuleName returns a finding's sub rule name if it exists.
func (f *Finding) RuleName() string {
	return f.base.JSONPayload.DetectionCategory.RuleName
}

// SubRuleName returns a finding's sub rule name if it exists.
func (f *Finding) SubRuleName() string {
	return f.base.JSONPayload.DetectionCategory.SubRuleName
}

// AffectedResource returns the first resource name from the affected resource..
func (f *Finding) AffectedResource() string {
	m := extractResource.FindStringSubmatch(f.base.JSONPayload.AffectedResources[0].GCPResourceName)
	if m == nil {
		return ""
	}
	return m[1]
}

// ProjectID returns the project ID of affected project.
func (f *Finding) ProjectID() string {
	return f.base.JSONPayload.Properties.ProjectID
}
