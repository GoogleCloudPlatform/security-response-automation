//  Copyright 2019 Google LLC
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  	https://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

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
// l

import (
	"context"
	"log"

	"github.com/googlecloudplatform/threat-automation/entities"
	"github.com/googlecloudplatform/threat-automation/providers/sha"

	"cloud.google.com/go/pubsub"
	"github.com/pkg/errors"
)

// RemovePublicIP removes all the external IP addresses of a GCE instance.
func RemovePublicIP(ctx context.Context, m pubsub.Message, ent *entities.Entity) error {

	finding, err := sha.NewComputeInstanceScanner(&m)
	if err != nil {
		return errors.Wrap(err, "failed to read finding")
	}

	if finding.Category() != "PUBLIC_IP_ADDRESS" {
		log.Printf("Unknown compute instance scanner category: %s. Skipping execution.", finding.Category())
		return nil
	}

	if err := ent.Resource.IfProjectInFolders(ctx, ent.Configuration.RemovePublicIP.Resources.FolderIDs, finding.ProjectID(), removePublicIP(ctx, finding, ent.Host)); err != nil {
		return err
	}

	if err := ent.Resource.IfProjectInProjects(ctx, ent.Configuration.RemovePublicIP.Resources.ProjectIDs, finding.ProjectID(), removePublicIP(ctx, finding, ent.Host)); err != nil {
		return err
	}

	return nil
}

func removePublicIP(ctx context.Context, finding *sha.ComputeInstanceScanner, host *entities.Host) func() error {
	return func() error {
		if err := host.RemoveExternalIPs(ctx, finding.ProjectID(), finding.Zone(), finding.Instance()); err != nil {
			return errors.Wrap(err, "failed to remove public ip:")
		}
		return nil
	}
}
