package etd

import (
	"regexp"
	"strings"
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

var (
	// extractInstance used to extract a instance.
	extractInstance = regexp.MustCompile(`/instances/(.*)$`)
	// extractZone used to extract a zone.
	extractZone = regexp.MustCompile(`/zones/([^/]*)`)
	// project ID key name in IAM Anomalous Grant finding from SCC Notification.
	iamAnomalousGrantProjectIDKey = "properties_project_id"
	// prefix from external members key in IAM Anomalous Grant finding from SCC Notification.
	iamAnomalousGrantExternalMembersPrefix = "properties_externalMembers_"
)

// Instance returns the instance name from the source instance string.
func Instance(resource string) string {
	i := extractInstance.FindStringSubmatch(resource)
	if len(i) != 2 {
		return ""
	}
	return i[1]
}

// Zone returns the zone from the source instance string.
func Zone(resource string) string {
	i := extractZone.FindStringSubmatch(resource)
	if len(i) != 2 {
		return ""
	}
	return i[1]
}

// IAMAnomalousGrantProjectID returns the project id from SCC IAM Anomalous Grant finding.
func IAMAnomalousGrantProjectID(sourceProperties map[string]string) string {
	return sourceProperties[iamAnomalousGrantProjectIDKey]
}

// IAMAnomalousGrantExternalMembers returns the external members from SCC IAM Anomalous Grant finding.
func IAMAnomalousGrantExternalMembers(sourceProperties map[string]string) []string {
	var externalMembers []string
	for k, v := range sourceProperties {
		if strings.HasPrefix(k, iamAnomalousGrantExternalMembersPrefix) {
			externalMembers = append(externalMembers, v)
		}
	}
	return externalMembers
}
