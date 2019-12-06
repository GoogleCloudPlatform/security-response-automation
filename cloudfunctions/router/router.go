package router

import (
	"context"
	"encoding/json"
	"log"

	"cloud.google.com/go/pubsub"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/createsnapshot"
	"github.com/googlecloudplatform/security-response-automation/providers/etd/badip"
	"github.com/googlecloudplatform/security-response-automation/providers/etd/sshbruteforce"
	"github.com/googlecloudplatform/security-response-automation/services"
	"github.com/pkg/errors"
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

var findings = []Namer{
	&sshbruteforce.Finding{},
	&badip.Finding{},
}

type Namer interface {
	RuleName([]byte) string
}

func actions(ruleName string) []string {
	return []string{}
}

// route wil pass the incoming finding to the correct remediation.
func route(ruleName, action string) {

}

// Services contains the services needed for this function.
type Services struct {
	Configuration *services.Configuration
	PubSub        *services.PubSub
}

type Values struct {
	Finding []byte
}

// routes
var foo = map[string][]interface{}{
	"bad_ip": {&createsnapshot.Values{}},
}

// Execute will route the incoming finding to the appropriate remediations.
func Execute(ctx context.Context, values *Values, services *Services) error {
	topic := ""
	for _, finding := range findings {
		n := finding.RuleName(values.Finding)
		log.Printf("got name: %s\n", n)
		log.Printf("ps: %+v\n", services.PubSub)
		if n != "" {
			// type is bad_ip
			// have an action for createsnapshot
			// send to createsnapshot serialize as createsnapshot.Values
			// return n
			log.Println("will publish")
			// var target createsnapshot.Values
			// b, err := json.Marshal(&target)
			for _, t := range foo[n] {
				b, err := json.Marshal(t)
				if err != nil {
					return err
				}
				log.Println("marshald")

				if _, err := services.PubSub.Publish(ctx, topic, &pubsub.Message{
					Data: b,
				}); err != nil {
					return errors.Wrapf(err, "failed to publish to %q", topic)
				}
			}

			return nil
		}
	}
	// name := extractRuleName(b)
	// fmt.Printf("name: %q", name)
	// if name == "" {
	// 	return ""
	// }
	// actions := actions(name)
	// for _, action := range actions {
	// 	route(name, action)
	// }
	// return name
	return nil
}
