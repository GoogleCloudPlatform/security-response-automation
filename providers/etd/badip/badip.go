// Package badip represents the bad IP finding.
package badip

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

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/createsnapshot"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/etd/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/etd"
)

// RuleName returns the rule name of the Stackdriver finding.
func (f *Finding) RuleName() string {
	name := ""
	if !f.useCSCC {
		name = f.badIP.GetJsonPayload().GetDetectionCategory().GetRuleName()
	}
	if name != "bad_ip" {
		return ""
	}
	return name
}

// Category returns the rule name of the SCC finding.
func (f *Finding) Category() string {
	category := ""
	if f.useCSCC {
		category = f.badIPCSCC.GetFinding().GetSourceProperties().GetDetectionCategoryRuleName()
	}
	if category != "bad_ip" {
		return ""
	}
	return category
}

// Finding represents a bad IP finding.
type Finding struct {
	useCSCC   bool
	badIP     *pb.BadIP
	badIPCSCC *pb.BadIPSCC
}

// New returns a new bad IP finding.
func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.badIP); err != nil {
		return nil, err
	}
	if f.badIP.GetJsonPayload().GetDetectionCategory().GetRuleName() != "" {
		return &f, nil
	}
	if err := json.Unmarshal(b, &f.badIPCSCC); err != nil {
		return nil, err
	}
	f.useCSCC = true
	return &f, nil
}

// CreateSnapshot returns values for the create snapshot automation.
func (f *Finding) CreateSnapshot() *createsnapshot.Values {
	if f.useCSCC {
		return &createsnapshot.Values{
			ProjectID: f.badIPCSCC.GetFinding().GetSourceProperties().GetPropertiesProjectId(),
			RuleName:  f.badIPCSCC.GetFinding().GetSourceProperties().GetDetectionCategoryRuleName(),
			Instance:  etd.Instance(f.badIPCSCC.GetFinding().GetSourceProperties().GetPropertiesInstanceDetails()),
			Zone:      etd.Zone(f.badIPCSCC.GetFinding().GetSourceProperties().GetPropertiesInstanceDetails()),
			Hash:      f.badIPCSCC.GetFinding().GetSecurityMarks().GetMarks().GetSraRemediated(),
			Name:      f.badIPCSCC.GetFinding().GetName(),
		}
	}
	return &createsnapshot.Values{
		ProjectID: f.badIP.GetJsonPayload().GetProperties().GetProjectId(),
		RuleName:  f.badIP.GetJsonPayload().GetDetectionCategory().GetRuleName(),
		Instance:  etd.Instance(f.badIP.GetJsonPayload().GetProperties().GetInstanceDetails()),
		Zone:      etd.Zone(f.badIP.GetJsonPayload().GetProperties().GetInstanceDetails()),
	}
}

// StringToBeHashed returns the string that will be used to generate the mark hash finding.
func (f *Finding) StringToBeHashed() string {
	return f.badIPCSCC.GetFinding().GetEventTime() + f.badIPCSCC.GetFinding().GetName()
}

// SraRemediated returns the sraRemediate mark of the finding.
func (f *Finding) SraRemediated() string {
	if f.useCSCC {
		return f.badIPCSCC.GetFinding().GetSecurityMarks().GetMarks().GetSraRemediated()
	}
	return ""
}

// Deserialize deserializes the finding in object.
func (f *Finding) Deserialize(b []byte) error {
	err := json.Unmarshal(b, &f.badIP)
	if err == nil {
		if f.badIP.GetJsonPayload().GetDetectionCategory().GetRuleName() != "" {
			return nil
		}
	}
	if err := json.Unmarshal(b, &f.badIPCSCC); err != nil {
		return err
	}
	f.useCSCC = true
	return nil
}
