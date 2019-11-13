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
	"context"
	"testing"

	"cloud.google.com/go/pubsub"
	"github.com/google/go-cmp/cmp"
	"github.com/googlecloudplatform/security-response-automation/clients/stubs"
)

func TestPubSub(t *testing.T) {
	tests := []struct {
		name    string
		message *pubsub.Message
	}{
		{
			name:    "publish",
			message: &pubsub.Message{Data: []byte("pubsub message")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stub := &stubs.PubSubStub{}
			stub.StubbedTopic = &pubsub.Topic{}
			ctx := context.Background()

			e := NewPubSub(stub)
			if _, err := e.Publish(ctx, "topic-id", tt.message); err != nil {
				t.Errorf("%s failed: %q", tt.name, err)
			}
			if diff := cmp.Diff(stub.PublishedMessage.Data, tt.message.Data); diff != "" {
				t.Errorf("%s failed diff:%q", tt.name, diff)
			}
		})
	}
}
