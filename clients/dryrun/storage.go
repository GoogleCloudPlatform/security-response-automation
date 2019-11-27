package dryrun

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

	"cloud.google.com/go/iam"
	"github.com/googlecloudplatform/security-response-automation/clients"
)

// Storage client.
type Storage struct {
	serviceClient *clients.Storage
}

// NewDryRunStorage returns and initializes the Storage client.
func NewDryRunStorage(original *clients.Storage) (*Storage, error) {
	return &Storage{serviceClient: original}, nil
}

// SetBucketPolicy sets the policy for the given bucket.
func (s *Storage) SetBucketPolicy(ctx context.Context, bucketName string, policy *iam.Policy) error {
	log.Printf("dry_run on, would call 'SetBucketPolicy' with params bucketName: %q, policy: %+v", bucketName, policy)
	return nil
}

// BucketPolicy gets the IAM policy for the given bucket.
func (s *Storage) BucketPolicy(ctx context.Context, bucketName string) (*iam.Policy, error) {
	return s.serviceClient.BucketPolicy(ctx, bucketName)
}

// EnableBucketOnlyPolicy enables the bucket only policy for the given bucket.
func (s *Storage) EnableBucketOnlyPolicy(ctx context.Context, bucketName string) error {
	log.Printf("dry_run on, would call 'EnableBucketOnlyPolicy' with params bucketName: %q", bucketName)
	return nil
}
