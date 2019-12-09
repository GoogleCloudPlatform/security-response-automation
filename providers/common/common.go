// Package common supplies a common struct for all finding providers.
package common

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

// Fields holds common fields used by providers.
type Fields struct {
	projectID string
	ruleName  string
	instance  string
	zone      string
}

// SetProjectID sets the projectID value.
func (f *Fields) SetProjectID(projectID string) { f.projectID = projectID }

// SetRuleName sets the ruleName value.
func (f *Fields) SetRuleName(ruleName string) { f.ruleName = ruleName }

// SetInstance sets the instance value.
func (f *Fields) SetInstance(instance string) { f.instance = instance }

// SetZone sets the zone value.
func (f *Fields) SetZone(zone string) { f.zone = zone }

// ProjectID returns the projectID value.
func (f *Fields) ProjectID() string { return f.projectID }

// RuleName returns the ruleName value.
func (f *Fields) RuleName() string { return f.ruleName }

// Instance returns the instance value.
func (f *Fields) Instance() string { return f.instance }

// Zone returns the zone value.
func (f *Fields) Zone() string { return f.zone }
