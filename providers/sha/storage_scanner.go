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
	"strings"

	"cloud.google.com/go/pubsub"
	"github.com/pkg/errors"
)

const resourcePrefix = "//storage.googleapis.com/"

// StorageScanner is an abstraction around SHA's IAM Scanner finding.
type StorageScanner struct {
	// Fields found in every SHA finding not specific to this finding.
	*Finding
}

// NewStorageScanner reads a pubsub message and creates a new finding.
func NewStorageScanner(ps *pubsub.Message) (*StorageScanner, error) {
	f := StorageScanner{}

	nf, err := NewFinding(ps)
	if err != nil {
		return nil, errors.New(err.Error())
	}

	f.Finding = nf

	if err := f.validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

func (f *StorageScanner) validate() error {

	if f.ScannerName() != "STORAGE_SCANNER" {
		return errors.New("not a STORAGE_SCANNER Finding")
	}

	return nil
}

// BucketName returns name of the bucket. Resource assumed valid due to prior validate call.
func (f *StorageScanner) BucketName() string {
	return strings.Split(f.ResourceName(), resourcePrefix)[1]
}
