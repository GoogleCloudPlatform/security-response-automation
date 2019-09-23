// Package entities holds commonly used methods used in security automation.
package entities

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
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"

	"cloud.google.com/go/pubsub"
)

const (
	// etdFindingSuffix is the log name suffix used by Event Threat Detection's findings.
	etdFindingSuffix = "/logs/threatdetection.googleapis.com%2Fdetection"
)

var (
	// ErrUnmarshal thrown when unable to unmarshal.
	ErrUnmarshal = errors.New("failed to unmarshal")
	// ErrParsing thrown when unable to parse.
	ErrParsing = errors.New("not a valid log")
	// ErrValueNotFound thrown when a value is requested but not found.
	ErrValueNotFound = errors.New("value not found")

	// extractProject used to extract a project Number from an affected resource.
	extractProject = regexp.MustCompile(`/projects/(.*)$`)
	// extractResource used to extract a resource.
	extractResource = regexp.MustCompile(`/([^/]+?/[^/]+?)?$`)
	// extractInstance used to extract a instance.
	extractInstance = regexp.MustCompile(`/instances/(.*)$`)
)

// stackdriverLog struct fits StackDriver logs.
type stackdriverLog struct {
	InsertID string `json:"insertId"`
	LogName  string `json:"logName"`
}

type etdLog struct {
	JSONPayload struct {
		DetectionCategory struct {
			SubRuleName string
			RuleName    string
		}
		AffectedResources []struct {
			GCPResourceName string
		}
		Properties struct {
			ProjectID string `json:"project_id"`
		}
	}
}

// Anomalous IAM grant external member added sub rule properties.
type externalMemberAdded struct {
	JSONPayload struct {
		Properties struct {
			ExternalMembers []string
		}
	}
}

// badNetworkFinding contains any finding based off VPC flow logs.
type badNetworkFinding struct {
	JSONPayload struct {
		Properties struct {
			Location       string
			SourceInstance string
			IP             []string
		}
	}
}

// Finding struct setting.
type Finding struct {
	// Properties associated with Stackdriver.
	sd stackdriverLog
	// Properties associated with an ETD finding.
	etd etdLog
	// Properties for ETD's anomalous IAM grant detector sub rule 'external member added to policy'.
	ext externalMemberAdded
	// Properties for any ETD finding based off VPC flow logs.
	badNetwork badNetworkFinding
}

// NewFinding returns a new finding.
func NewFinding() *Finding {
	return &Finding{}
}

// ReadFinding unmarshals a finding from PubSub.
func (f *Finding) ReadFinding(m *pubsub.Message) error {
	if err := json.Unmarshal(m.Data, &f.sd); err != nil {
		log.Println("failed to read stackdriver finding")
		return ErrUnmarshal
	}

	if f.sd.LogName == "" {
		return ErrParsing
	}

	if !strings.HasSuffix(f.sd.LogName, etdFindingSuffix) {
		return ErrParsing
	}

	if err := json.Unmarshal(m.Data, &f.etd); err != nil {
		return ErrUnmarshal
	}

	switch f.etd.JSONPayload.DetectionCategory.SubRuleName {
	// case for external user granted as project editor.
	case "external_member_added_to_policy":
		if err := json.Unmarshal(m.Data, &f.ext); err != nil {
			log.Println("failed to read ext")
			return ErrUnmarshal
		}
	// case for external user granted as project owner.
	case "external_member_invited_to_policy":
		if err := json.Unmarshal(m.Data, &f.ext); err != nil {
			fmt.Println("fil2")
			return ErrUnmarshal
		}
	}

	switch f.etd.JSONPayload.DetectionCategory.RuleName {
	case "bad_ip":
		fallthrough
	case "bad_domain":
		if err := json.Unmarshal(m.Data, &f.badNetwork); err != nil {
			return ErrUnmarshal
		}
	}

	return nil
}

// ExternalMembers returns a slice of external members.
func (f *Finding) ExternalMembers() []string {
	return f.ext.JSONPayload.Properties.ExternalMembers
}

// ProjectID returns the projectID of the affected project.
func (f *Finding) ProjectID() string {
	return f.etd.JSONPayload.Properties.ProjectID
}

// ProjectNumber returns the project number of the affected resource, or an empty string if it can't find one.
func (f *Finding) ProjectNumber() string {
	aff := f.etd.JSONPayload.AffectedResources
	if len(aff) == 0 {
		return ""
	}
	results := extractProject.FindStringSubmatch(aff[0].GCPResourceName)
	if len(results) != 2 {
		return ""
	}
	return results[1]
}

// Resource returns the resource of affected project.
func (f *Finding) Resource() string {
	aff := f.etd.JSONPayload.AffectedResources
	if len(aff) == 0 {
		return ""
	}
	m := extractResource.FindStringSubmatch(aff[0].GCPResourceName)
	if m == nil {
		return ""
	}
	return m[1]

}

// ExternalUsers returns the external members found from an anomalous IAM grant.
func (f *Finding) ExternalUsers() []string {
	if f.ext.JSONPayload.Properties.ExternalMembers == nil {
		return []string{}
	}

	return f.ext.JSONPayload.Properties.ExternalMembers
}

// Zone returns the zone of affected project.
func (f *Finding) Zone() string {
	return f.badNetwork.JSONPayload.Properties.Location
}

// RuleName returns the rule name.
func (f *Finding) RuleName() string {
	return f.etd.JSONPayload.DetectionCategory.RuleName
}

// Instance returns the instance name of affected project.
func (f *Finding) Instance() string {
	s := f.badNetwork.JSONPayload.Properties.SourceInstance
	if s == "" {
		return ""
	}
	i := extractInstance.FindStringSubmatch(s)
	if len(i) != 2 {
		return ""
	}
	return i[1]
}

// BadIPs returns a slice of bad IPs from an ETD bad IP finding.
func (f *Finding) BadIPs() []string {
	return f.badNetwork.JSONPayload.Properties.IP
}
