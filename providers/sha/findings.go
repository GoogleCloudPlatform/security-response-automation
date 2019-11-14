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
	"regexp"
	"strings"
)

const resourcePrefix = "//storage.googleapis.com/"

var (
	// extractZone is a regex to extract the zone of the instance that is on the external uri.
	extractZone = regexp.MustCompile(`/zones/(.+)/instances`)
	// extractInstance is a regex to extract the name of the instance that is on the external uri.
	extractInstance = regexp.MustCompile(`/instances/(.+)`)
	// extractDataset is a regex to extract the dataset ID that is on the resource name.
	extractDataset = regexp.MustCompile(`/datasets/(.+)`)
	// extractFirewallID is a regex to extract the firewall ID that is on the resource name.
	extractFirewallID = regexp.MustCompile(`/global/firewalls/(.*)$`)
	// extractClusterZone is a regex to extract the zone of the cluster that is on the resource name.
	extractClusterZone = regexp.MustCompile(`/zones/(.+)/clusters`)
	// extractClusterID is a regex to extract the Cluster ID of the cluster that is on the resource name.
	extractClusterID = regexp.MustCompile(`/clusters/(.+)`)
	// extractOrganizationID is a regex to extract the organizationID value from a resource string.
	extractOrganizationID = regexp.MustCompile(`organizations/(.+)/sources`)
)

// GenericFindingState is a finding that exposes its state.
type GenericFindingState interface {
	GetState() string
}

// IgnoreFinding returns if this finding should be ignored or not.
func IgnoreFinding(finding GenericFindingState) bool {
	return finding.GetState() != "ACTIVE"
}

// Zone returns the zone of the instance.
func Zone(resource string) string {
	return extractZone.FindStringSubmatch(resource)[1]
}

// Instance returns the name of the instance.
func Instance(resource string) string {
	return extractInstance.FindStringSubmatch(resource)[1]
}

// Dataset returns the ID of the BigQuery dataset.
func Dataset(resource string) string {
	return extractDataset.FindStringSubmatch(resource)[1]
}

// BucketName returns name of the bucket. Resource assumed valid due to prior validate call.
func BucketName(resource string) string {
	return strings.Split(resource, resourcePrefix)[1]
}

// FirewallID returns the numerical ID of the firewall.
func FirewallID(resource string) string {
	return extractFirewallID.FindStringSubmatch(resource)[1]
}

// ClusterZone returns the zone of the cluster.
func ClusterZone(resource string) string {
	return extractClusterZone.FindStringSubmatch(resource)[1]
}

// ClusterID returns the cluster id of the cluster.
func ClusterID(resource string) string {
	return extractClusterID.FindStringSubmatch(resource)[1]
}

// OrganizationID returns the organization name.
func OrganizationID(resource string) string {
	return extractOrganizationID.FindStringSubmatch(resource)[1]
}
