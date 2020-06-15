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
	if ff.UseCSCC {
		name = ff.BadIPCSCC.GetFinding().GetSourceProperties().GetDetectionCategory().GetRuleName()
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
	UseCSCC   bool
	badIP     *pb.BadIP
	BadIPCSCC *pb.BadIPSCC
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
	if err := json.Unmarshal(b, &f.BadIPCSCC); err != nil {
		return nil, err
	}
	f.UseCSCC = true
	return &f, nil
}

// CreateSnapshot returns values for the create snapshot automation.
func (f *Finding) CreateSnapshot() *createsnapshot.Values {
	if f.UseCSCC {
		return &createsnapshot.Values{
			ProjectID: f.BadIPCSCC.GetFinding().GetSourceProperties().GetProperties().GetNetwork().GetProject(),
			RuleName:  f.BadIPCSCC.GetFinding().GetSourceProperties().GetDetectionCategory().GetRuleName(),
			Instance:  etd.Instance(f.BadIPCSCC.GetFinding().GetSourceProperties().GetProperties().GetInstanceDetails()),
			Zone:      etd.Zone(f.BadIPCSCC.GetFinding().GetSourceProperties().GetProperties().GetInstanceDetails()),
		}
	}
	return &createsnapshot.Values{
		ProjectID: f.badIP.GetJsonPayload().GetProperties().GetNetwork().GetProject(),
		RuleName:  f.badIP.GetJsonPayload().GetDetectionCategory().GetRuleName(),
		Instance:  etd.Instance(f.badIP.GetJsonPayload().GetProperties().GetInstanceDetails()),
		Zone:      etd.Zone(f.badIP.GetJsonPayload().GetProperties().GetInstanceDetails()),
	}
}
