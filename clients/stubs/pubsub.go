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
	"context"

	"cloud.google.com/go/pubsub"
)

// PubSubStub provides a stub for the PubSub client.
type PubSubStub struct {
	StubbedTopic     *pubsub.Topic
	PublishedMessage *pubsub.Message
}

// Topic returns a reference to a topic.
func (p *PubSubStub) Topic(id string) *pubsub.Topic {
	return p.StubbedTopic
}

// Publish will publish a message to a PubSub topic.
func (p *PubSubStub) Publish(ctx context.Context, topic *pubsub.Topic, message *pubsub.Message) (string, error) {
	p.PublishedMessage = message
	return "", nil
}
