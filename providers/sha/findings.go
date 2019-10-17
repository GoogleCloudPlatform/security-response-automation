// Package sha holds Security Health Analytics finding entities and functions
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
	"encoding/json"
	"log"

	"cloud.google.com/go/pubsub"
	"github.com/googlecloudplatform/threat-automation/entities"
	"github.com/pkg/errors"
)

type baseFinding struct {
	NotificationConfigName string
	Finding                struct {
		Name             string
		Parent           string
		ResourceName     string
		State            string
		Category         string
		ExternalURI      string
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
		SecurityMarks struct {
			Name  string
			Marks map[string]string
		}
		EventTime  string
		CreateTime string
	}
}

// Finding represents SHA findings.
type Finding struct {
	base *baseFinding

	firewallScanner        *FirewallScanner
	IAMScanner             *IamScanner
	StorageScanner         *StorageScanner
	ComputeInstanceScanner *ComputeInstanceScanner
}

// NewFinding returns a new SHA finding.
func NewFinding(m *pubsub.Message) (*Finding, error) {
	f := &Finding{}
	if err := json.Unmarshal(m.Data, &f.base); err != nil {
		return nil, errors.Wrap(entities.ErrUnmarshal, err.Error())
	}
	if ok := f.validate(); !ok {
		return nil, entities.ErrValueNotFound
	}
	switch f.ScannerName() {
	case "FIREWALL_SCANNER":
		ff := &FirewallScanner{}
		ff.Finding = f
		if err := open(m, ff); err != nil {
			return nil, err
		}
		f.firewallScanner = ff
	case "IAM_SCANNER":
		ff := &IamScanner{}
		ff.Finding = f
		if err := open(m, ff); err != nil {
			return nil, err
		}
		log.Println("got ff")
		log.Printf("%+v\n", ff)
		f.IAMScanner = ff
	case "STORAGE_SCANNER":
		ff := &StorageScanner{}
		ff.Finding = f
		if err := open(m, ff); err != nil {
			return nil, err
		}
		f.StorageScanner = ff
	case "COMPUTE_INSTANCE_SCANNER":
		ff := &ComputeInstanceScanner{}
		ff.Finding = f
		if err := open(m, ff); err != nil {
			return nil, err
		}
		f.ComputeInstanceScanner = ff
	default:
		return nil, entities.ErrValueNotFound
	}
	return f, nil
}

func open(ps *pubsub.Message, dst entities.Interface) error {
	if err := json.Unmarshal(ps.Data, dst.Fields()); err != nil {
		return entities.ErrUnmarshal
	}
	if ok := dst.Validate(); !ok {
		return entities.ErrValueNotFound
	}
	return nil
}

func (f *Finding) validate() bool {
	return f.ResourceName() != "" || f.Category() != ""
}

// ResourceName returns the finding's affected resource.
func (f *Finding) ResourceName() string {
	return f.base.Finding.ResourceName
}

// Category returns the category of the finding.
func (f *Finding) Category() string {
	return f.base.Finding.Category
}

// ScannerName returns the scanner name from the finding.
func (f *Finding) ScannerName() string {
	return f.base.Finding.SourceProperties.ScannerName
}

// ProjectID returns the affected project ID.
func (f *Finding) ProjectID() string {
	return f.base.Finding.SourceProperties.ProjectID
}
