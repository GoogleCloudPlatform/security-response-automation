package stubs

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

	"cloud.google.com/go/iam"
)

// StorageStub provides a stub for the Storage client.
type StorageStub struct {
	BucketPolicyResponse  *iam.Policy
	RemoveBucketPolicy    *iam.Policy
	EnabledPolicyOnBucket string
}

// SetBucketPolicy set a policy for the given bucket.
func (s *StorageStub) SetBucketPolicy(ctx context.Context, bucketName string, p *iam.Policy) error {
	s.RemoveBucketPolicy = p
	return nil
}

// BucketPolicy gets a bucket's policy.
func (s *StorageStub) BucketPolicy(ctx context.Context, bucketName string) (*iam.Policy, error) {
	return s.BucketPolicyResponse, nil
}

// EnableBucketOnlyPolicy saves the bucket that receives the request for enabling bucket only policy.
func (s *StorageStub) EnableBucketOnlyPolicy(ctx context.Context, bucketName string) error {
	s.EnabledPolicyOnBucket = bucketName
	return nil
}
