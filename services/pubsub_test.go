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
	"log"
	"testing"

	"cloud.google.com/go/pubsub"
	"github.com/googlecloudplatform/threat-automation/clients/stubs"
)

func TestFoo(t *testing.T) {
	const (
		projectID = "test-project"
		datasetID = "test-dataset"
	)
	tests := []struct {
		name    string
		message *pubsub.Message
		topic   *pubsub.Topic
	}{
		{
			name:    "foo",
			message: &pubsub.Message{Data: []byte("foo-tom")},
			topic:   &pubsub.Topic{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stub := &stubs.PubSubStub{}
			stub.StubbedTopic = tt.topic
			stub.StubbedResult = &pubsub.PublishResult{}
			ctx := context.Background()
			log.Println("2")

			ps := NewPubSub(stub)
			log.Printf("2: %+v", ps)
			_, err := ps.Publish(ctx, "topic-id", tt.message)
			log.Println("2")
			if err != nil {
				t.Errorf("%s failed: %q", tt.name, err)
			}
		})
	}
}
