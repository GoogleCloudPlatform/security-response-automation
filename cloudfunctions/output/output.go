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
	"encoding/json"
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
	Configuration *Configuration
	Logger        *services.Logger
	PubSub        *services.PubSub
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

// ChannelMessage contains the required values for this function.
type ChannelMessage struct {
	CorrelationID  string
	Timestamp      string
	AutomationName string
	SourceInfo     string
	Priority       string
	Status         string
	SensitiveInfo  bool
	Subject        string
	Message        string
}

// Execute will orchestrate the notification to the available channel.
func Execute(ctx context.Context, c *ChannelMessage, s *Services) error {
	switch c.SourceInfo {
	case "turbinia":
		log.Printf("executing output %q", c.SourceInfo)
		values := &turbinia.Values{
			ProjectID: s.Configuration.Spec.Outputs.Turbinia.ProjectID,
			Topic:     s.Configuration.Spec.Outputs.Turbinia.Topic,
			Zone:      s.Configuration.Spec.Outputs.Turbinia.Zone,
			DiskName:  c.Message,
		}
		if values.ProjectID == "" || values.Topic == "" || values.Zone == "" {
			return errors.New("missing Turbinia config values")
		}
		topic := topics[c.SourceInfo].Topic
		b, err := json.Marshal(&values)
		if err != nil {
			return err
		}
		if _, err := s.PubSub.Publish(ctx, topic, &pubsub.Message{
			Data: b,
		}); err != nil {
			s.Logger.Error("failed to publish to %q for channel %q", topic, c.SourceInfo)
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
