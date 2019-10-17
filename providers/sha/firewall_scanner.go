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
	"regexp"
)

// extractFirewallID is a regex to extract the firewall ID that is on the resource name
var extractFirewallID = regexp.MustCompile(`/global/firewalls/(.*)$`)

// FirewallScanner represents a SHA Firewall Scanner finding.
type FirewallScanner struct {
	*Finding

	fields struct {
		Finding struct {
			SourceProperties struct {
				Allowed           string
				AllowedIPRange    string
				ActivationTrigger string
				SourceRange       string
			}
		}
	}
}

// Fields returns this finding's fields.
func (f *FirewallScanner) Fields() interface{} { return &f.fields }

// Validate confirms if this finding's fields are correct.
func (f *FirewallScanner) Validate() bool { return true }

// FirewallID returns the numerical ID of the firewall.
func (f *FirewallScanner) FirewallID() string {
	return extractFirewallID.FindStringSubmatch(f.ResourceName())[1]
}
