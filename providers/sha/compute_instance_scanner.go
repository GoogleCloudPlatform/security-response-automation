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

	"github.com/googlecloudplatform/threat-automation/entities"

	"cloud.google.com/go/pubsub"
	"github.com/pkg/errors"
)

// extractZone is a regex to extract the zone of the instance that is on the external uri.
var extractZone = regexp.MustCompile(`/zones/(.+)/instances`)

// extractInstance is a regex to extract the name of the instance that is on the external uri.
var extractInstance = regexp.MustCompile(`/instances/(.+)`)

// ComputeInstanceScanner a Security Health Analytics finding from Compute Instance Scanner.
type ComputeInstanceScanner struct {
	*Finding
}

// NewFirewallScanner creates a new FirewallScanner
func NewComputeInstanceScanner(ps *pubsub.Message) (*ComputeInstanceScanner, error) {
	f := ComputeInstanceScanner{}

	nf, err := NewFinding(ps)
	if err != nil {
		return nil, err
	}

	f.Finding = nf

	if !f.validate() {
		return nil, errors.Wrap(entities.ErrValueNotFound, "not a COMPUTE_INSTANCE_SCANNER Finding")
	}

	return &f, nil
}

func (f *ComputeInstanceScanner) validate() bool {
	return f.ScannerName() == "COMPUTE_INSTANCE_SCANNER"
}

// Zone returns the zone of the instance.
func (f *ComputeInstanceScanner) Zone() string {
	return extractZone.FindStringSubmatch(f.ExternalURI())[1]
}

// Instance returns the name of the instance.
func (f *ComputeInstanceScanner) Instance() string {
	return extractInstance.FindStringSubmatch(f.ExternalURI())[1]
}
