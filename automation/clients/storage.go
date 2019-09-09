/*
Package clients provides the required clients for taking automated actions.

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
package clients

import (
	"fmt"

	"cloud.google.com/go/storage"
	stg "cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

// Storage is the interface used by STG.
type Storage interface {
	RemoveBucketUsers(string, stg.ACLEntity) error
}

// InstantiateStorage initializes the Storage client.
func InstantiateStorage(c *Client) error {
	stg, err := storage.NewClient(c.ctx, option.WithCredentialsFile(authFile))
	if err != nil {
		return fmt.Errorf("failed to init storage: %q", err)
	}
	c.stg = stg
	return nil
}

// RemoveBucketUsers deletes the users for the given bucket.
func (c *Client) RemoveBucketUsers(bucketName string, entity storage.ACLEntity) error {
	if err := c.stg.Bucket(bucketName).ACL().Delete(c.ctx, entity); err != nil {
		return fmt.Errorf("failed to remove bucket users: %q", err)
	}
	return nil
}
