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
	"fmt"

	"cloud.google.com/go/pubsub"
	securitycenter "cloud.google.com/go/securitycenter/apiv1"
	"google.golang.org/api/option"
	securitycenterpb "google.golang.org/genproto/googleapis/cloud/securitycenter/v1"
	"google.golang.org/genproto/protobuf/field_mask"
)

// CreateSecurityMarks will create Security Marks for findings
func CreateSecurityMarks(ctx context.Context, m pubsub.Message) error {
	// TODO(amandakarina): Read this from a SHA finding. Faking for now.
	const authFile string = "/home/CIT/amandak/Documents/google-notification-provider/setup/service_accounts/scc-query-builder-dev-qb-clsecteam-service-account.json"
	client, err := securitycenter.NewClient(ctx, option.WithCredentialsFile(authFile))
	if err != nil {
		return fmt.Errorf("securitycenter.NewClient: %v", err)
	}

	defer client.Close() // Closing the client safely cleans up background resources.

	var assetName string = "organizations/1055058813388/sources/10229098525863118226/findings/21e362f9d2db5cc29613b025bc1b64d3"
	req := &securitycenterpb.UpdateSecurityMarksRequest{
		// If not set or empty, all marks would be cleared before
		// adding the new marks below.
		UpdateMask: &field_mask.FieldMask{
			Paths: []string{"marks.test_go", "marks.client_go"},
		},
		SecurityMarks: &securitycenterpb.SecurityMarks{
			Name: fmt.Sprintf("%s/securityMarks", assetName),
			// Note keys correspond to the last part of each path.
			Marks: map[string]string{"test_go": "worked", "client_go": "uhull"},
		},
	}
	updatedMarks, err := client.UpdateSecurityMarks(ctx, req)
	if err != nil {
		return fmt.Errorf("UpdateSecurityMarks: %v", err)
	}

	fmt.Printf("Updated marks: %s\n", updatedMarks.Name)
	for k, v := range updatedMarks.Marks {
		fmt.Printf("%s = %s\n", k, v)
	}
	return nil
}
