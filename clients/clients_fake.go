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
	stg "cloud.google.com/go/storage"
	crm "google.golang.org/api/cloudresourcemanager/v1"
	cs "google.golang.org/api/compute/v1"
	pb "google.golang.org/genproto/googleapis/cloud/securitycenter/v1beta1"
)

// MockClients holds provides implementations of clients.
type MockClients struct {
	fakeGetPolicyResponse    *crm.Policy
	fakeGetAncestryResponse  []string
	fakeListDisks            *cs.DiskList
	fakeListProjectSnapshots *cs.SnapshotList
	SavedSetPolicy           *crm.Policy
	SavedFirewallRule        *cs.Firewall
	SavedRemoveBucketUsers   stg.ACLEntity
	SavedCreateSnapshots     map[string]cs.Snapshot
}

// NewMockClients requires a new instance of Clients.
func NewMockClients() *MockClients {
	return &MockClients{
		SavedCreateSnapshots: make(map[string]cs.Snapshot),
	}
}

// AddGetPolicyFake adds fake bindings for GetPolicy.
func (m *MockClients) AddGetPolicyFake(b []*crm.Binding) {
	m.fakeGetPolicyResponse = &crm.Policy{Bindings: b}
}

// AddGetProjectAncestryFake adds fake bindings for GetProjectAncestry.
func (m *MockClients) AddGetProjectAncestryFake(r []string) {
	m.fakeGetAncestryResponse = r
}

// AddListDisksFake adds fake disk list for ListDisks.
func (m *MockClients) AddListDisksFake(d []*cs.Disk) {
	m.fakeListDisks = &cs.DiskList{Items: d}
}

// AddListProjectSnapshotsFake adds fake snapshot list for ListProjectSnapshots.
func (m *MockClients) AddListProjectSnapshotsFake(s []*cs.Snapshot) {
	m.fakeListProjectSnapshots = &cs.SnapshotList{Items: s}
}

// GetPolicyProject is a fake implementation of Cloud Resource Manager's GetIamPolicy.
func (m *MockClients) GetPolicyProject(projectID string) (*crm.Policy, error) {
	return m.fakeGetPolicyResponse, nil
}

// SetPolicyProject is a fake implementation of Cloud Resource Manager's SetIamPolicy.
func (m *MockClients) SetPolicyProject(projectID string, p *crm.Policy) (*crm.Policy, error) {
	m.SavedSetPolicy = p
	return m.SavedSetPolicy, nil
}

// UpdateFinding is a fake implementation of SCC's Updatefinding.
func (m *MockClients) UpdateFinding(req *pb.UpdateFindingRequest) (*pb.Finding, error) {
	return &pb.Finding{}, nil
}

// GetProjectAncestry is a fake implementation of Cloud Resource Manager's GetAncestry.
func (m *MockClients) GetProjectAncestry(_ string) ([]string, error) {
	return m.fakeGetAncestryResponse, nil
}

// PatchFirewallRule updates the firewall rule for the given project.
func (m *MockClients) PatchFirewallRule(_, _ string, rb *cs.Firewall) (*cs.Operation, error) {
	m.SavedFirewallRule = rb
	return nil, nil
}

// RemoveBucketUsers removes the users for the given bucket.
func (m *MockClients) RemoveBucketUsers(_ string, entity stg.ACLEntity) error {
	m.SavedRemoveBucketUsers = entity
	return nil
}

// CreateSnapshot creates a snapshot of a specified persistent disk.
func (m *MockClients) CreateSnapshot(_, _, disk string, rb *cs.Snapshot) (*cs.Operation, error) {
	m.SavedCreateSnapshots[disk] = *rb
	return nil, nil
}

// DeleteDiskSnapshot deletes a snapshot.
func (m *MockClients) DeleteDiskSnapshot(_, _ string) (*cs.Operation, error) {
	return nil, nil
}

// ListProjectSnapshots returns a list of snapshot resources.
func (m *MockClients) ListProjectSnapshots(_ string) (*cs.SnapshotList, error) {
	return m.fakeListProjectSnapshots, nil
}

// ListDisks returns a list of disks.
func (m *MockClients) ListDisks(_, _ string) (*cs.DiskList, error) {
	return m.fakeListDisks, nil
}

// SetLabels sets the labels on a snapshot.
func (m *MockClients) SetLabels(_, _ string, rb *cs.GlobalSetLabelsRequest) (*cs.Operation, error) {
	return nil, nil
}

// WaitGlobal waits globally.
func (m *MockClients) WaitGlobal(_ string, _ *cs.Operation) []error {
	return []error{}
}

// WaitZone zone waits at the zone level.
func (m *MockClients) WaitZone(_, _ string, _ *cs.Operation) []error {
	return []error{}
}
