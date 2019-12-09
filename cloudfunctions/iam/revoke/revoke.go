// Package revoke provides the implementation of automated actions.
package revoke

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
	"io/ioutil"
	"regexp"
	"strings"

	"github.com/googlecloudplatform/security-response-automation/services"
	"gopkg.in/yaml.v2"
)

// Values contains the required values needed for this function.
type Values struct {
	ProjectID       string
	ExternalMembers []string
}

// Services contains the services needed for this function.
type Services struct {
	Configuration *Configuration
	Resource      *services.Resource
	Logger        *services.Logger
}

type Properties struct {
	DryRun       bool     `yaml:"dry_run"`
	AllowDomains []string `yaml:"allow_domains"`
}

type Configuration struct {
	Spec struct {
		Match      services.Match
		Validation struct {
			OpenAPIV3Schema struct {
				Properties Properties
			} `yaml:"openAPIV3Schema"`
		}
	}
}

// Config will return the automations' configuration.
func Config() (*Configuration, error) {
	var c Configuration
	b, err := ioutil.ReadFile("./cloudfunctions/iam/revoke/config.yaml")
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Execute is the entry point for the IAM revoker Cloud Function.
//
// This automation will remove users from a project's policy if:
// - The users are believed to be external as reported from the finding provider.
// - The project where the external users were found are within the set configured resources.
// - The users do not match the list of allowed domains.
//
func Execute(ctx context.Context, values *Values, services *Services) error {
	properties := services.Configuration.Spec.Validation.OpenAPIV3Schema.Properties
	matches := services.Configuration.Spec.Match
	members, err := toRemove(values.ExternalMembers, properties.AllowDomains)
	if err != nil {
		return err
	}
	return services.Resource.CheckMatches(ctx, &matches, values.ProjectID, func() error {
		if properties.DryRun {
			services.Logger.Info("dry_run on, would have removed %q from %q", members, values.ProjectID)
			return nil
		}
		if err := services.Resource.RemoveUsersProject(ctx, values.ProjectID, members); err != nil {
			return err
		}
		services.Logger.Info("successfully removed %q from %s", members, values.ProjectID)
		return nil
	})
}

// toRemove returns a slice containing only external members that are disallowed.
// This check is done to ensure we only consider removing members that came from the finding and not
// just any members that aren't part of the configured allow list.
func toRemove(members []string, allowed []string) ([]string, error) {
	allowedList := strings.Replace(strings.Join(allowed, "|"), ".", `\.`, -1)
	allowedRegExp, err := regexp.Compile("^.+@" + allowedList + "$")
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex: %q", err)
	}
	remove := []string{}
	for _, user := range members {
		if allowedRegExp.MatchString(user) {
			continue
		}
		remove = append(remove, user)

	}
	return remove, nil
}
