package output

// Copyright 2020 Google LLC
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
	"io/ioutil"
	"log"

	"cloud.google.com/go/pubsub"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/output/turbinia"
	"github.com/googlecloudplatform/security-response-automation/services"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

var topics = map[string]struct{ Topic string }{
	"turbinia": {Topic: "notify-turbinia"},
}

// Configuration maps outputs attributes.
type Configuration struct {
	APIVersion string
	Spec       struct {
		Outputs struct {
			Turbinia turbinia.Values `yaml:"turbinia"`
		}
	}
}

// Services contains the services needed for this function.
type Services struct {
	Logger *services.Logger
	PubSub *services.PubSub
}

// Config will return the output's configuration.
func Config() (*Configuration, error) {
	var c Configuration
	b, err := ioutil.ReadFile("./cloudfunctions/output/config.yaml")
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Values are requirements for this function.
type Values struct {
	OutputID      string
	OutputMessage []byte
}

// Execute will orchestrate the notification to the available channel.
func Execute(ctx context.Context, v *Values, s *Services) error {
	switch v.OutputID {
	case "turbinia":
		log.Printf("executing output %q", v.OutputID)
		topic := topics[v.OutputID].Topic
		if _, err := s.PubSub.Publish(ctx, topic, &pubsub.Message{
			Data: v.OutputMessage,
		}); err != nil {
			s.Logger.Error("failed to publish to %q for channel %q", topic, v.OutputID)
			return err
		}
		log.Printf("sent to pubsub topic: %q", topic)
	case "pagerduty":
	case "slack":
	case "sendgrid":
	case "stackdriver":
	default:
		return errors.Errorf("Invalid channel option")
	}
	return nil
}
