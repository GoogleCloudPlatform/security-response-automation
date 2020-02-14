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
	"errors"
	"io/ioutil"
	"log"

	"cloud.google.com/go/pubsub"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/output/sendgrid"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/output/turbinia"
	"github.com/googlecloudplatform/security-response-automation/services"
	"gopkg.in/yaml.v2"
)

var topics = map[string]struct{ Topic string }{
	"turbinia": {Topic: "notify-turbinia"},
	"sendgrid": {Topic: "notify-sendgrid"},
}

// Configuration maps outputs attributes.
type Configuration struct {
	APIVersion string
	Spec       struct {
		Outputs struct {
			Turbinia turbinia.Values `yaml:"turbinia"`
			Sendgrid sendgrid.Values `yaml:"sendgrid"`
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
	b, err := ioutil.ReadFile("./cloudfunctions/router/config.yaml")
	if err != nil {
		log.Fatalf("error getting configuration file %s", err)
		return nil, err
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Values are requirements for this function.
type Values struct {
	Name    string
	Message []byte
}

// Execute will route & publish the incoming message to the appropriate output function.
func Execute(ctx context.Context, v *Values, services *Services) error {
	log.Printf("executing output %q", v.Name)
	if topic, ok := topics[v.Name]; ok {
		if _, err := services.PubSub.Publish(ctx, topic.Topic, &pubsub.Message{Data: v.Message}); err != nil {
			services.Logger.Error("failed to publish to %q for %q - %q", topic, v.Name, err)
			return err
		}

		log.Printf("sent to pubsub topic: %q", topic.Topic)
		return nil
	}

	services.Logger.Error("Invalid output option")
	return errors.New("invalid output option")
}
