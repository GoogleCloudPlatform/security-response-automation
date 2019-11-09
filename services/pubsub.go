package services

import (
	"context"
	"log"

	"cloud.google.com/go/pubsub"
)

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

// PubSubClient contains minimum interface required by the service.
type PubSubClient interface {
	Topic(string) *pubsub.Topic
	Publish(context.Context, *pubsub.Topic, *pubsub.Message) *pubsub.PublishResult
}

// PubSub service.
type PubSub struct {
	client PubSubClient
}

// NewPubSub returns a PubSub service.
func NewPubSub(cs PubSubClient) *PubSub {
	return &PubSub{client: cs}
}

// Publish will publish a message to a PubSub topic.
func (p *PubSub) Publish(ctx context.Context, topicID string, message *pubsub.Message) (string, error) {
	topic := p.client.Topic(topicID)
	log.Println("1")
	// defer topic.Stop()
	res := p.client.Publish(ctx, topic, message)
	log.Println("1")
	id, err := res.Get(ctx)
	log.Println("1")
	if err != nil {
		return "", nil
	}
	log.Println("1")
	return id, nil
}
