package createsnapshot

import (
	"encoding/json"

	etdPb "github.com/googlecloudplatform/security-response-automation/compiled/etd/protos"
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

// ruleName will attempt to extract the rule name from the incoming finding.
func etdRuleName(b []byte) string {
	detectors := []interface{}{
		&etdPb.SshBruteForce{},
		&etdPb.BadIP{},
	}
	for _, v := range detectors {
		if err := json.Unmarshal(b, v); err != nil {
			return ""
		}
		name := v.(etdPb.SshBruteForce).JsonPayload.GetDetectionCategory().GetRuleName()
		if name != "" {
			return name
		}
	}
	return ""
}

func extractRuleName(b []byte) string {
	n := etdRuleName(b)
	if n != "" {
		return n
	}
	// add other providers, include StackDriver and CSCC notifications.
	return ""
}

func actions(ruleName string) []string {
	return []string{}
}

// route wil pass the incoming finding to the correct remediation.
func route(ruleName, action string) {

}

// Execute will route the incoming finding to the appropriate remediations.
func Execute(b []byte) {
	name := extractRuleName(b)
	if name == "" {
		return
	}
	actions := actions(name)
	for _, action := range actions {
		route(name, action)
	}
}
