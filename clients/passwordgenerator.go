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

import "github.com/google/uuid"

// PasswordGenerator client.
type PasswordGenerator struct{}

// NewPasswordGenerator returns a Password Generator entity.
func NewPasswordGenerator() (*PasswordGenerator, error) {
	return &PasswordGenerator{}, nil
}

// GeneratePassword generates a password based in a randomly generated uuid.
func (pg *PasswordGenerator) GeneratePassword() string {
	uuid := uuid.New()
	return uuid.String()
}
