package clients

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
//
// TODO:
// 		- Move API key to an environment variable.
// 		- Support more VT requests.
// 		- Possibly also support official VT Go API https://github.com/VirusTotal/vt-go

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
)

// Sample holds a subset of fields returned in a sample request.
type Sample struct {
	SHA256 string `json:"sha256"`
}

// DomainReport holds a subset of fields returned in a domain request.
type DomainReport struct {
	Samples []Sample `json:"detected_communicating_samples"`
}

const (
	/*
		Key contains the ViruslTotal API key.
		https://developers.virustotal.com/reference#getting-started
	*/
	key = ""
	/*
		Domain API URL
		- Note here we are using v2 of the API [0] and not the VT provided Go library [1] due to
		  domains not being included in that library.
		[0] https://developers.virustotal.com/reference#domain-report
		[1] https://github.com/VirusTotal/vt-go
	*/
	domainURL = "https://www.virustotal.com/vtapi/v2/domain/report?domain=%s&apikey=%s"
)

// SamplesFromDomain returns a slice of hashes associated with a domain name.
func SamplesFromDomain(domain string) ([]string, error) {
	resp, err := http.Get(fmt.Sprintf(domainURL, domain, key))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("request failed, missing API key?")
	}
	defer resp.Body.Close()
	dr := new(DomainReport)
	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil {
		return nil, errors.Wrap(err, "error decoding json for domain report")
	}
	ss := []string{}
	for _, s := range dr.Samples {
		ss = append(ss, s.SHA256)
	}
	return ss, nil
}
