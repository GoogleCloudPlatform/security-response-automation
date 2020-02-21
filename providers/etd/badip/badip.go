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

// Name returns the rule name of the finding.
func (f *Finding) Name(b []byte) string {
	ff, err := New(b)
	if err != nil {
		return ""
	}
	name := ""
	if ff.useCSCC {
		name = ff.badIPCSCC.GetFinding().GetSourceProperties().GetDetectionCategoryRuleName()
	} else {
		name = ff.badIP.GetJsonPayload().GetDetectionCategory().GetRuleName()
	}
	if name != "bad_ip" {
		return ""
	}
	return name
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
			Mark:      f.badIPCSCC.GetFinding().GetEventTime(),
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

// AlreadyRemediated returns if the finding was remediated before or not.
func (f *Finding) AlreadyRemediated() bool {
	if f.useCSCC {
		remediated := f.badIPCSCC.GetFinding().GetSecurityMarks().GetMarks()["sra-remediated-event-time"]
		return remediated == f.badIPCSCC.GetFinding().GetEventTime()
	}
	return false
}
