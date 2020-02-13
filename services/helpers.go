package services

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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"google.golang.org/api/cloudresourcemanager/v1"
)

// CreateAncestors creates an ancestry response using a provided slice of members.
func CreateAncestors(members []string) *cloudresourcemanager.GetAncestryResponse {
	ancestors := []*cloudresourcemanager.Ancestor{}
	for _, m := range members {
		mm := strings.Split(m, "/")
		ancestors = append(ancestors, &cloudresourcemanager.Ancestor{
			ResourceId: &cloudresourcemanager.ResourceId{
				Type: mm[0],
				Id:   mm[1],
			},
		})
	}
	return &cloudresourcemanager.GetAncestryResponse{Ancestor: ancestors}
}

// GeneratePassword generates a password based on randomly generated numbers that are hashed using SHA256.
func GeneratePassword() (string, error) {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	sha := sha256.Sum256(b)
	return hex.EncodeToString(sha[:]), nil
}
