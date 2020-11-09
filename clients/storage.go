package clients

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

	"cloud.google.com/go/iam"
	"cloud.google.com/go/storage"
)

// Storage client.
type Storage struct {
	service *storage.Client
}

// NewStorage returns and initializes the Storage client.
func NewStorage(ctx context.Context) (*Storage, error) {
	c, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to init storage: %q", err)
	}
	return &Storage{service: c}, nil
}

// SetBucketPolicy sets the policy for the given bucket.
func (s *Storage) SetBucketPolicy(ctx context.Context, bucketName string, policy *iam.Policy) error {
	return s.service.Bucket(bucketName).IAM().SetPolicy(ctx, policy)
}

// BucketPolicy gets the IAM policy for the given bucket.
func (s *Storage) BucketPolicy(ctx context.Context, bucketName string) (*iam.Policy, error) {
	return s.service.Bucket(bucketName).IAM().Policy(ctx)
}

// EnableBucketOnlyPolicy enables the bucket only policy for the given bucket.
func (s *Storage) EnableBucketOnlyPolicy(ctx context.Context, bucketName string) error {
	enableBucketPolicyOnly := storage.BucketAttrsToUpdate{
		BucketPolicyOnly: &storage.BucketPolicyOnly{
			Enabled: true,
		},
	}
	if _, err := s.service.Bucket(bucketName).Update(ctx, enableBucketPolicyOnly); err != nil {
		return err
	}
	return nil
}
