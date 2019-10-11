// Package cloudfunctions provides the implementation of automated actions.
package cloudfunctions

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
	"log"
	"strings"

	"github.com/googlecloudplatform/threat-automation/entities"
	"github.com/googlecloudplatform/threat-automation/providers/etd"
	"github.com/pkg/errors"

	"cloud.google.com/go/pubsub"
)

// RevokeExternalGrantsFolders is the entry point of the Cloud Function.
//
// This Cloud Function will read the incoming finding, if it's an ETD anomalous IAM grant
// identicating an external member was invited to policy check to see if the external member
// is in a list of disallowed domains.
//
// Additionally check to see if the affected project is in the specified folder. If the grant
// was to a domain explicitly disallowed and within the folder then remove the member from the
// entire IAM policy for the resource.
func RevokeExternalGrantsFolders(ctx context.Context, m pubsub.Message, r *entities.Resource, folderIDs []string, disallowed []string, l *entities.Logger) error {
	f, err := etd.NewExternalMembersFinding(&m)
	if err != nil {
		return errors.Wrap(err, "failed to read finding")
	}

	log.Printf("listing project %q ancestors", f.ProjectID())

	ancestors, err := r.GetProjectAncestry(ctx, f.ProjectID())
	if err != nil {
		return errors.Wrap(err, "failed to get project ancestry")
	}

	log.Printf("ancestors returned from project %q: %v", f.ProjectID(), ancestors)

	remove := toRemove(f.ExternalMembers(), disallowed)
	for _, resource := range ancestors {
		for _, folderID := range folderIDs {
			if resource != "folders/"+folderID {
				continue
			}

			l.Info("removing users %v from folder %q project %q", remove, folderID, f.ProjectID())

			if _, err = r.RemoveMembersProject(ctx, f.ProjectID(), remove); err != nil {
				return errors.Wrap(err, "failed to remove disallowed domains")
			}
		}
	}
	return nil
}

// toRemove returns a slice containing only external members that are disallowed.
func toRemove(members []string, disallowed []string) []string {
	r := []string{}
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
