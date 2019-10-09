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

	"github.com/googlecloudplatform/threat-automation/entities"

	"cloud.google.com/go/pubsub"
	"github.com/pkg/errors"
)

type iamScanner struct {
	Finding struct {
		Name             string
		SourceProperties struct {
			OffendingIamRoles string
		}
	}
}

// IamScanner is an abstraction around SHA's IAM Scanner finding.
type IamScanner struct {
	// Fields found in every SHA finding not specific to this finding.
	*Finding
	// Fields specific to this finding.
	fields iamScanner
}

// NewIamScanner reads a pubsub message and creates a new finding.
func NewIamScanner(ps *pubsub.Message) (*IamScanner, error) {
	f := IamScanner{}

	nf, err := NewFinding(ps)
	if err != nil {
		return nil, errors.New(err.Error())
	}

	f.Finding = nf

	if err := json.Unmarshal(ps.Data, &f.fields); err != nil {
		return nil, entities.ErrUnmarshal
	}

	if !f.validate() {
		return nil, errors.New("not a IAM_SCANNER Finding")
	}
	return &f, nil
}

func (f *IamScanner) validate() bool {
	return f.ScannerName() == "IAM_SCANNER" 
}
