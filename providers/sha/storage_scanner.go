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
)

// resourcePrefix the prefix of the full name of a bucket
// on the resource name filed of an SCC SHA Finding
const resourcePrefix = "//storage.googleapis.com/"

// StorageScanner is an abstraction around SHA's IAM Scanner finding.
type StorageScanner struct {
	*Finding
	
	fields struct{}
}

// Fields returns this finding's fields.
func (f *StorageScanner) Fields() interface{} { return &f.fields }

// Validate confirms if this finding's fields are correct.
func (f *StorageScanner) Validate() bool { return f.ScannerName() == "STORAGE_SCANNER" }

// BucketName returns name of the bucket. Resource assumed valid due to prior validate call.
func (f *StorageScanner) BucketName() string {
	return strings.Split(f.ResourceName(), resourcePrefix)[1]
}
