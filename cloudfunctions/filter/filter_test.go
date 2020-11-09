package filter

// Copyright 2020 Google LLC
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
	"context"
	"strings"
	"testing"
)

type tsException struct {
	regoSource     []byte
	findingJSON    []byte
	regoFilename   string
	expectedResult bool
	expectedError  string
}

func TestIsException(t *testing.T) {
	ctx := context.Background()
	for _, ts := range exceptionTestSuites {
		filterName := strings.Split(ts.regoFilename, ".")[0]
		actualResult, err := isException(ctx, ts.findingJSON, ts.regoSource, filterName)
		if err != nil {
			if !strings.Contains(err.Error(), ts.expectedError) {
				t.Errorf("unexpected error returned for %s: %s", ts.regoFilename, err)
			}
		}
		if actualResult != ts.expectedResult {
			t.Errorf("expected %v got %v for %s", ts.expectedResult, actualResult, filterName)
		}
	}
}

var exceptionTestSuites = []tsException{
	tsException{
		expectedResult: true,
		expectedError:  "",
		regoFilename:   "ntpd1.rego",
		regoSource: []byte(`package sra.filter
		ntpd1 {
			ipcon := input.finding.sourceProperties.properties.ipConnection
			ipcon.destPort == 123
			ipcon.protocol == 17
		}`),
		findingJSON: []byte(`{
			"finding": {
				"sourceProperties": {
					"properties": {
						"ipConnection": {
							"destIp": "x.x.x.x",
							"destPort": 123,
							"srcPort": 34720,
							"srcIp": "y.y.y.y",
							"protocol": 17
						}
					},
					"detectionPriority": "HIGH"
				},
				"state": "ACTIVE",
				"category": "Malware: Bad IP"
			}
		}`),
	},
	tsException{
		expectedResult: false,
		expectedError:  "",
		regoFilename:   "ntpd2.rego",
		regoSource: []byte(`package sra.filter
		ntpd2 {
			ipcon := input.finding.sourceProperties.properties.ipConnection
			ipcon.destPort == 123
			ipcon.protocol == 17
		}`),
		findingJSON: []byte(`{
			"finding": {
				"sourceProperties": {
					"properties": {
						"ipConnection": {
							"destIp": "x.x.x.x",
							"destPort": 443,
							"srcPort": 34720,
							"srcIp": "y.y.y.y",
							"protocol": 6
						}
					},
					"detectionPriority": "HIGH"
				},
				"state": "ACTIVE",
				"category": "Malware: Bad IP"
			}
		}`),
	},
	tsException{
		expectedResult: false,
		expectedError:  "rego_parse_error",
		regoFilename:   "ntpd3.rego",
		regoSource: []byte(`package sra.filter
		ntpd3
			ipcon := input.finding.sourceProperties.properties.ipConnection
			ipcon.destPort == 123
			ipcon.protocol == 17
		}`),
		findingJSON: []byte(`{
			"finding": {
				"sourceProperties": {
					"properties": {
						"ipConnection": {
							"destIp": "x.x.x.x",
							"destPort": 443,
							"srcPort": 34720,
							"srcIp": "y.y.y.y",
							"protocol": 6
						}
					},
					"detectionPriority": "HIGH"
				},
				"state": "ACTIVE",
				"category": "Malware: Bad IP"
			}
		}`),
	},
}
