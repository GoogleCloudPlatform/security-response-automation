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

var (
	// extractZone is a regex to extract the zone of the instance that is on the external uri.
	extractZone = regexp.MustCompile(`/zones/(.+)/instances`)

	// extractInstance is a regex to extract the name of the instance that is on the external uri.
	extractInstance = regexp.MustCompile(`/instances/(.+)`)
)

// ComputeInstanceScanner represents a SHA Compute Istance Scanner finding.
type ComputeInstanceScanner struct {
	*Finding

	fields *struct{}
}

// Fields returns this finding's fields.
func (f *ComputeInstanceScanner) Fields() interface{} { return &f.fields }

// Validate confirms if this finding's fields are correct.
func (f *ComputeInstanceScanner) Validate() bool { return true }

// Zone returns the zone of the instance.
func (f *ComputeInstanceScanner) Zone() string {
	return extractZone.FindStringSubmatch(f.ResourceName())[1]
}

// Instance returns the name of the instance.
func (f *ComputeInstanceScanner) Instance() string {
	return extractInstance.FindStringSubmatch(f.ResourceName())[1]
}
