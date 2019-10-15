package stubs

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
	"github.com/sendgrid/rest"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

// SendGridStub provides a stub for the Email client.
type SendGridStub struct {
	StubbedSend    *rest.Response
	StubbedSendErr error
}

// Send to send email
func (e *SendGridStub) Send(mail *mail.SGMailV3) (*rest.Response, error) {
	return e.StubbedSend, e.StubbedSendErr
}
