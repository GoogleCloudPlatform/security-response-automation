package services

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
	"fmt"
	"testing"

	"github.com/pkg/errors"
)

func TestParseTemplateEmail(t *testing.T) {

	var sampleTemplate = "%s Admin, Security Response Automation"

	type sampleContent struct {
		Greeting string
	}

	tests := []struct {
		name             string
		expectedError    error
		expectedResponse string
		template         string
		templateContent  interface{}
	}{
		{
			name:             "test parse email success",
			template:         "testdata/sample.tmpl",
			templateContent:  struct{ Content sampleContent }{Content: sampleContent{Greeting: "Hello!"}},
			expectedError:    nil,
			expectedResponse: fmt.Sprintf(sampleTemplate, "Hello!"),
		},
		{
			name:             "test parse not found file",
			template:         "testdata/unknown.tmpl",
			templateContent:  nil,
			expectedError:    errLoadTemplate,
			expectedResponse: "",
		},
		{
			name:             "test parse execution fail",
			template:         "testdata/sample.tmpl",
			templateContent:  struct{ Unknown string }{Unknown: "content"},
			expectedError:    errParseTemplate,
			expectedResponse: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			email := NewEmail(nil)
			res, err := email.RenderTemplate(tt.template, tt.templateContent)

			if tt.expectedError != errors.Cause(err) {
				t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expectedError, err)
			}

			if exp, got := tt.expectedResponse, res; err == nil && exp != got {
				t.Errorf("%v failed exp:%v got:%v", tt.name, got, exp)
			}
		})
	}
}
