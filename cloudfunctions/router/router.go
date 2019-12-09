package router

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
	"encoding/json"
	"io/ioutil"
	"log"

	"cloud.google.com/go/pubsub"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/createsnapshot"
	"github.com/googlecloudplatform/security-response-automation/providers/common"
	"github.com/googlecloudplatform/security-response-automation/providers/etd/badip"
	"github.com/googlecloudplatform/security-response-automation/providers/etd/sshbruteforce"
	"github.com/googlecloudplatform/security-response-automation/services"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

var findings = []Namer{
	&sshbruteforce.Finding{},
	&badip.Finding{},
}

// Name represents findings that export their name.
type Namer interface {
	Name([]byte) string
}

// Services contains the services needed for this function.
type Services struct {
	PubSub              *services.PubSub
	RouterConfiguration *RouterConfiguration
}

// Values contains the required values for this function.
type Values struct {
	Finding []byte
}

// topics maps automation targets to PubSub topics.
var topics = map[string]struct{ Topic string }{
	"gce_create_disk_snapshot": {Topic: "threat-findings-create-disk-snapshot"},
}

// Automation defines which remediation function to call.
type Automation struct {
	Action string
}

// RouterConfiguration maps findings to automations.
type RouterConfiguration struct {
	APIVersion string
	Spec       struct {
		Name       string
		Parameters struct {
			ETD struct {
				BadIP []Automation `yaml:"bad_ip"`
			}
		}
	}
}

// Config will return the router's configuration.
func Config() (*RouterConfiguration, error) {
	var c RouterConfiguration
	b, err := ioutil.ReadFile("./cloudfunctions/router/config.yaml")
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// ruleName will attempt to deserialize all findings until a name is extracted.
func ruleName(b []byte) string {
	for _, finding := range findings {
		if n := finding.Name(b); n != "" {
			return n
		}
	}
	return ""
}

// Execute will route the incoming finding to the appropriate remediations.
func Execute(ctx context.Context, values *Values, services *Services) error {
	name := ruleName(values.Finding)
	log.Printf("configuration: %+v", services.RouterConfiguration)
	var automations []Automation
	var fields common.Fields

	switch name {
	case "bad_ip":
		automations = services.RouterConfiguration.Spec.Parameters.ETD.BadIP
		f, err := badip.Populate(values.Finding)
		if err != nil {
			return err
		}
		fields.SetProjectID(f.ProjectID)
		fields.SetRuleName(f.RuleName)
		fields.SetInstance(f.Instance)
		fields.SetZone(f.Zone)
	// case "bad_domain":
	// 	automations = services.RouterConfiguration.Spec.Parameters.ETD.BadIP
	// case "sshscanner":
	// 	automations = services.RouterConfiguration.Spec.Parameters.ETD.BadIP
	// case "openbucket":
	// 	automations = services.RouterConfiguration.Spec.Parameters.ETD.BadIP
	default:
		return errors.New("foo")
	}

	for _, automation := range automations {
		log.Printf("automation: %q", automation.Action)
		switch automation.Action {
		case "gce_create_disk_snapshot":
			v := &createsnapshot.Values{
				ProjectID: fields.ProjectID(),
				RuleName:  fields.RuleName(),
				Instance:  fields.Instance(),
				Zone:      fields.Zone(),
			}
			b, err := json.Marshal(v)
			if err != nil {
				return err
			}
			log.Printf("publishing to: %q", topics[automation.Action].Topic)
			if _, err := services.PubSub.Publish(ctx, topics[automation.Action].Topic, &pubsub.Message{
				Data: b,
			}); err != nil {
				return errors.Wrapf(err, "failed to publish to %q for action %q", topics[automation.Action].Topic, automation.Action)
			}
		default:
			return errors.New("foo")
		}
		log.Println("done")
	}
	return nil
}
