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

// IamScanner represents a SHA IAM Scanner finding.
type IamScanner struct {
	*Finding

	fields struct {
		Finding struct {
			Name             string
			SourceProperties struct {
				OffendingIamRoles string
			}
		}
	}
}

// Fields returns this finding's fields.
func (f *IamScanner) Fields() interface{} { return &f.fields }

// Validate confirms if this finding's fields are correct.
func (f *IamScanner) Validate() bool { return true }

// OffendingIamRoles returns the offending IAM roles.
func (f *IamScanner) OffendingIamRoles() string {
	return f.fields.Finding.SourceProperties.OffendingIamRoles
}
