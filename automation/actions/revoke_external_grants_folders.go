/*
Package actions provides the implementation of automated actions.

Copyright 2019 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package actions

import (
	"log"

	"github.com/GoogleCloudPlatform/threat-automation/automation/clients"
	"github.com/GoogleCloudPlatform/threat-automation/automation/finding"
	"github.com/GoogleCloudPlatform/threat-automation/automation/user"

	"context"
	"fmt"
	"strings"

	"cloud.google.com/go/pubsub"
)

/*
RevokeExternalGrantsFolders is the entry point of the Cloud Function.

This Cloud Function will read the incoming finding, if it's an ETD anomalous IAM grant
identicating an external member was invited to policy check to see if the external member
is in a list of disallowed domains.

Additionally check to see if the affected project is in the specified folder. If the grant
was to a domain explicitly disallowed and within the folder then remove the member from the
entire IAM policy for the resource.

*/
func RevokeExternalGrantsFolders(ctx context.Context, m pubsub.Message, c clients.Clients, folderIDs []string, disallowed []string) error {
	f := finding.NewFinding()

	if err := f.ReadFinding(&m); err != nil {
		return fmt.Errorf("failed to read finding: %q", err)
	}

	if eu := f.ExternalUsers(); len(eu) == 0 {
		return fmt.Errorf("no external users")
	}
	log.Printf("got %d external users\n", len(f.ExternalUsers()))

	ancestors, err := c.GetProjectAncestry(f.ProjectID())
	if err != nil {
		return fmt.Errorf("failed to get project ancestry: %q", err)
	}
	u := user.NewUser(c)
	remove := toRemove(f, disallowed)
	for _, resource := range ancestors {
		for _, folderID := range folderIDs {
			log.Printf("%s - %s\n", resource, folderID)
			if resource != "folders/"+folderID {
				continue
			}
			if _, err = u.RemoveMembersProject(f.ProjectID(), remove); err != nil {
				return fmt.Errorf("failed to remove disallowed domains: %q", err)
			}
		}
	}
	return nil
}

// toRemove returns a slice containing only external members that are disallowed.
func toRemove(f *finding.Finding, disallowed []string) []string {
	r := []string{}
	members := f.ExternalMembers()
	for _, mm := range members {
		for _, d := range disallowed {
			if !strings.HasSuffix(mm, d) {
				continue
			}
			r = append(r, mm)
		}
	}
	return r
}
