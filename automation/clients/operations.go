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
	"log"
	"time"

	cs "google.golang.org/api/compute/v1"
)

const (
	// Maximum number of loops (where each loop is defined below) to wait.
	maxLoops    = 180
	loopSeconds = 5
)

// OperationsService is the interface used by Operations.
type OperationsService interface {
	WaitZone(string, string, *cs.Operation) []error
	WaitGlobal(string, *cs.Operation) []error
}

// InstantiateOperations instantiates a operations service.
func InstantiateOperations(c *Client) {
	c.opsZone = cs.NewZoneOperationsService(c.cs)
	c.opsGlobal = cs.NewGlobalOperationsService(c.cs)
}

type waiter func() (*cs.Operation, error)

// WaitZone will wait for the zonal operation to complete.
func (c *Client) WaitZone(project, zone string, op *cs.Operation) []error {
	return wait(op, func() (*cs.Operation, error) {
		return c.opsZone.Get(project, zone, fmt.Sprintf("%d", op.Id)).Do()
	})
}

// WaitGlobal will wait for the global operation to complete.
func (c *Client) WaitGlobal(project string, op *cs.Operation) []error {
	return wait(op, func() (*cs.Operation, error) {
		return c.opsGlobal.Get(project, fmt.Sprintf("%d", op.Id)).Do()
	})
}

func wait(op *cs.Operation, fn waiter) []error {
	if op.Error != nil {
		return returnErrorCodes(op.Error.Errors)
	}
	for i := 0; i < maxLoops; i++ {
		o, err := fn()
		if err != nil {
			return []error{err}
		}
		if o.Error != nil {
			return returnErrorCodes(o.Error.Errors)
		}
		if o.Status == "DONE" {
			return nil
		}
		if i%4 == 0 {
			log.Println("Waiting")
		}
		time.Sleep(loopSeconds * time.Second)
	}
	return []error{fmt.Errorf("Operation timed out: %q", op.Name)}
}

func returnErrorCodes(errors []*cs.OperationErrorErrors) []error {
	out := []error{}
	for _, err := range errors {
		out = append(out, fmt.Errorf(err.Code))
	}
	return out
}
