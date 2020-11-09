package clients

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
	"fmt"

	"cloud.google.com/go/pubsub"
)

// PubSub client.
type PubSub struct {
	client *pubsub.Client
}

// NewPubSub returns the PubSub client.
func NewPubSub(ctx context.Context, projectID string) (*PubSub, error) {
	client, err := pubsub.NewClient(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to init pubsub: %q", err)
	}
	return &PubSub{client: client}, nil
}

// Topic returns a reference to a topic.
func (p *PubSub) Topic(id string) *pubsub.Topic {
	return p.client.Topic(id)
}

// Publish will publish a message to a PubSub topic.
func (p *PubSub) Publish(ctx context.Context, topic *pubsub.Topic, message *pubsub.Message) (string, error) {
	defer topic.Stop()
	return topic.Publish(ctx, message).Get(ctx)
}
