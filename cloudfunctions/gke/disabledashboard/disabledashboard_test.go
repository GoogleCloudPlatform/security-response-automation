package disabledashboard

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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/googlecloudplatform/threat-automation/clients/stubs"
	"github.com/googlecloudplatform/threat-automation/services"
	"golang.org/x/xerrors"
	crm "google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/container/v1"
)

func TestReadFinding(t *testing.T) {
	const (
		webUIFinding = `{
		"notificationConfigName": "organizations/154584661726/notificationConfigs/sampleConfigId",
		"finding": {
			"name": "organizations/119612413569/sources/7086426792249889955/findings/18db063343328e25a3997efaa0126274",
			"parent": "organizations/119612413569/sources/7086426792249889955",
			"resourceName": "//container.googleapis.com/projects/test-cat-findings-clseclab/zones/us-central1-a/clusters/ex-abuse-cluster-3",
			"state": "ACTIVE",
			"category": "WEB_UI_ENABLED",
			"externalUri": "https://console.cloud.google.com/kubernetes/clusters/details/us-central1-a/ex-abuse-cluster-3?project=test-cat-findings-clseclab",
			"sourceProperties": {
				"ReactivationCount": 0,
				"ExceptionInstructions": "Add the security mark \"allow_web_ui_enabled\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
				"SeverityLevel": "High",
				"Recommendation": "Go to https://console.cloud.google.com/kubernetes/clusters/details/us-central1-a/ex-abuse-cluster-3?project=test-cat-findings-clseclab then click \"Edit\", click \"Add-ons\", and disable \"Kubernetes dashboard\". Note that a cluster cannot be modified while it is reconfiguring itself.",
				"ProjectId": "test-cat-findings-clseclab",
				"AssetCreationTime": "2018-09-26T23:57:19+00:00",
				"ScannerName": "CONTAINER_SCANNER",
				"ScanRunId": "2019-09-30T18:20:20.151-07:00",
				"Explanation": "The Kubernetes web UI is backed by a highly privileged Kubernetes Service Account, which can be abused if compromised. If you are already using the GCP console, the Kubernetes web UI extends your attack surface unnecessarily. Learn more about how to disable the Kubernetes web UI and other techniques for hardening your Kubernetes clusters at https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#disable_kubernetes_dashboard"
			},
			"securityMarks": {
				"name": "organizations/119612413569/sources/7086426792249889955/findings/18db063343328e25a3997efaa0126274/securityMarks"
			},
			"eventTime": "2019-10-01T01:20:20.151Z",
			"createTime": "2019-03-05T22:21:01.836Z"
		}
	  }`
		wrongCategory = `{
		"notificationConfigName": "organizations/154584661726/notificationConfigs/sampleConfigId",
		"finding": {
			"name": "organizations/119612413569/sources/7086426792249889955/findings/18db063343328e25a3997efaa0126274",
			"parent": "organizations/119612413569/sources/7086426792249889955",
			"resourceName": "//container.googleapis.com/projects/test-cat-findings-clseclab/zones/us-central1-a/clusters/ex-abuse-cluster-3",
			"state": "ACTIVE",
			"category": "WRONG_CATEGORY",
			"externalUri": "https://console.cloud.google.com/kubernetes/clusters/details/us-central1-a/ex-abuse-cluster-3?project=test-cat-findings-clseclab",
			"sourceProperties": {
				"ReactivationCount": 0,
				"ExceptionInstructions": "Add the security mark \"allow_web_ui_enabled\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
				"SeverityLevel": "High",
				"Recommendation": "Go to https://console.cloud.google.com/kubernetes/clusters/details/us-central1-a/ex-abuse-cluster-3?project=test-cat-findings-clseclab then click \"Edit\", click \"Add-ons\", and disable \"Kubernetes dashboard\". Note that a cluster cannot be modified while it is reconfiguring itself.",
				"ProjectId": "test-cat-findings-clseclab",
				"AssetCreationTime": "2018-09-26T23:57:19+00:00",
				"ScannerName": "CONTAINER_SCANNER",
				"ScanRunId": "2019-09-30T18:20:20.151-07:00",
				"Explanation": "The Kubernetes web UI is backed by a highly privileged Kubernetes Service Account, which can be abused if compromised. If you are already using the GCP console, the Kubernetes web UI extends your attack surface unnecessarily. Learn more about how to disable the Kubernetes web UI and other techniques for hardening your Kubernetes clusters at https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#disable_kubernetes_dashboard"
			},
			"securityMarks": {
				"name": "organizations/119612413569/sources/7086426792249889955/findings/18db063343328e25a3997efaa0126274/securityMarks"
			},
			"eventTime": "2019-10-01T01:20:20.151Z",
			"createTime": "2019-03-05T22:21:01.836Z"
		}
	  }`
	)
	for _, tt := range []struct {
		name, projectID, zone, clusterID string
		bytes                            []byte
		expectedError                    error
	}{
		{name: "read", projectID: "test-cat-findings-clseclab", zone: "us-central1-a", clusterID: "ex-abuse-cluster-3", bytes: []byte(webUIFinding), expectedError: nil},
		{name: "wrong category", projectID: "", zone: "", clusterID: "", bytes: []byte(wrongCategory), expectedError: services.ErrUnsupportedFinding},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := ReadFinding(tt.bytes)
			if tt.expectedError == nil && err != nil {
				t.Errorf("%s failed: %q", tt.name, err)
			}
			if tt.expectedError != nil && err != nil && !xerrors.Is(err, tt.expectedError) {
				t.Errorf("%s failed: got:%q want:%q", tt.name, err, tt.expectedError)
			}
			if err == nil && r.ProjectID != tt.projectID {
				t.Errorf("%s failed: got:%q want:%q", tt.name, r.ProjectID, tt.projectID)
			}
			if err == nil && r.Zone != tt.zone {
				t.Errorf("%s failed: got:%q want:%q", tt.name, r.Zone, tt.zone)
			}
			if err == nil && r.ClusterID != tt.clusterID {
				t.Errorf("%s failed: got:%q want:%q", tt.name, r.ClusterID, tt.clusterID)
			}
		})
	}
}

func TestDisableDashboard(t *testing.T) {
	ctx := context.Background()

	test := []struct {
		name            string
		folderIDs       []string
		ancestry        *crm.GetAncestryResponse
		expectedRequest *container.SetAddonsConfigRequest
	}{
		{
			name:      "disable dashboard",
			folderIDs: []string{"123"},
			ancestry:  services.CreateAncestors([]string{"folder/123"}),
			expectedRequest: &container.SetAddonsConfigRequest{
				AddonsConfig: &container.AddonsConfig{
					KubernetesDashboard: &container.KubernetesDashboard{
						Disabled: true,
					},
				},
			},
		},
		{
			name:            "no valid folder",
			folderIDs:       []string{"456"},
			ancestry:        services.CreateAncestors([]string{"folder/123"}),
			expectedRequest: nil,
		},
	}
	for _, tt := range test {
		values, svcs, crmStub, contStub := disableDashboardSetup(tt.folderIDs)
		crmStub.GetAncestryResponse = tt.ancestry
		if err := Execute(ctx, values, &Services{
			Configuration: svcs.Configuration,
			Container:     svcs.Container,
			Resource:      svcs.Resource,
			Logger:        svcs.Logger,
		}); err != nil {
			t.Errorf("%s test failed want:%q", tt.name, err)
		}
		if diff := cmp.Diff(contStub.UpdatedAddonsConfig, tt.expectedRequest); diff != "" {
			t.Errorf("%v failed\n exp:%v\n got:%v", tt.name, tt.expectedRequest, contStub.UpdatedAddonsConfig)
		}
	}
}

func disableDashboardSetup(folderIDs []string) (*Values, *services.Global, *stubs.ResourceManagerStub, *stubs.ContainerStub) {
	loggerStub := &stubs.LoggerStub{}
	log := services.NewLogger(loggerStub)
	contStub := &stubs.ContainerStub{}
	cont := services.NewContainer(contStub)
	crmStub := &stubs.ResourceManagerStub{}
	storageStub := &stubs.StorageStub{}
	resource := services.NewResource(crmStub, storageStub)
	req := &Values{
		ProjectID: "project-test",
		Zone:      "us-central1-a",
		ClusterID: "test-cluster",
	}
	conf := &services.Configuration{
		DisableDashboard: &services.DisableDashboard{
			Resources: &services.Resources{
				FolderIDs: folderIDs,
			},
		},
	}
	return req, &services.Global{Logger: log, Configuration: conf, Resource: resource, Container: cont}, crmStub, contStub
}
