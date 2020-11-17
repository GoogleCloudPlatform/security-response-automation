package filter

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
	"cloud.google.com/go/pubsub"
	"context"
	"encoding/json"
	"fmt"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/filter/internal/storage"
	"github.com/googlecloudplatform/security-response-automation/services"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"os"
	"strings"
)

const outputTopicEnvVar = "OUTPUT_TOPIC"
const queryStringPrefix = "data.sra.filter"

// Services contains the services needed for this function.
type Services struct {
	PubSub                *services.PubSub
	Logger                *services.Logger
	SecurityCommandCenter *services.CommandCenter
}

// Without these two types, unmarshalling breaks since Finding_State
// is serialized as a string but it's actual value is an integer enum
type slimFinding struct {
	Name string
}

type notification struct {
	Finding slimFinding
}

// Execute will first check the raw finding against the user-supplied Rego policies
// then if it should be filtered, update the finding, otherwise pass it along to the
// router cloud function.
func Execute(ctx context.Context, m pubsub.Message, svcs *Services) (err error) {
	raw := m.Data
	var msg notification
	if err = json.Unmarshal(raw, &msg); err != nil {
		svcs.Logger.Info("Only SCC Notification format is supported. This message will not be filtered.")
	} else {
		// Iterate through rego filenames and content that are generated into code
		// in the internal/storage package. This happens as part of the terraform
		// apply automatically.
		for filename, content := range storage.FileStore {
			filterName := strings.Split(filename, ".")[0]
			exception, err := isException(ctx, raw, content, filterName)
			if err != nil {
				return err
			}
			if exception {
				err = updateFinding(ctx, svcs, filterName, msg.Finding.Name)
				if err != nil {
					svcs.Logger.Error("Failed to update finding %s", msg.Finding.Name)
					return err
				}
				svcs.Logger.Info("Marked finding %s with filter %s", msg.Finding.Name, filterName)
				return nil
			}
		}
	}
	topic, err := publish(ctx, svcs, raw)
	if err != nil {
		svcs.Logger.Error("Failed to publish to %s", topic)
		return err
	}
	svcs.Logger.Info("Forwarded finding to topic %s", topic)

	return nil
}

func isException(ctx context.Context, findingJSON, regoSource []byte, filterName string) (bool, error) {
	compiler, err := ast.CompileModules(map[string]string{
		filterName: string(regoSource),
	})
	if err != nil {
		return false, err
	}

	// Rego expects a string-keyed map so we can't unmarshal into a Finding yet
	var input map[string]interface{}
	if err := json.Unmarshal(findingJSON, &input); err != nil {
		return false, err
	}

	// Contruct query based on filename without the extension. For a rego file with
	// the name myrule.rego, this would expect the content to look like this:
	// package sra.filter
	// myrule {...}
	query := fmt.Sprintf("%s.%s", queryStringPrefix, filterName)
	r := rego.New(
		rego.Query(query),
		rego.Compiler(compiler),
		rego.Input(input))
	rs, err := r.Eval(ctx)
	if err != nil {
		return false, err
	}

	// If the finding matches, return true
	if len(rs) > 0 {
		return true, nil
	}
	return false, nil
}

func publish(ctx context.Context, svcs *Services, raw []byte) (string, error) {
	topic := os.Getenv(outputTopicEnvVar)
	if topic == "" {
		return "", fmt.Errorf("%s must not be empty", outputTopicEnvVar)
	}
	if _, err := svcs.PubSub.Publish(ctx, topic, &pubsub.Message{Data: raw}); err != nil {
		return "", err
	}
	return topic, nil
}

func updateFinding(ctx context.Context, svcs *Services, filterName string, findingName string) error {
	mark := map[string]string{"sra-filter": filterName}
	if _, err := svcs.SecurityCommandCenter.AddSecurityMarks(ctx, findingName, mark); err != nil {
		return err
	}
	if _, err := svcs.SecurityCommandCenter.SetInactive(ctx, findingName); err != nil {
		return err
	}
	return nil
}
