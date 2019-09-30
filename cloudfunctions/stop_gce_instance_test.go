package cloudfunctions

import (
	"context"
	"testing"

	"cloud.google.com/go/pubsub"
	"github.com/googlecloudplatform/threat-automation/clients/stubs"
	"github.com/googlecloudplatform/threat-automation/entities"
)

//StopInstance stops gce instance
func TestStopInstance(t *testing.T) {
	ctx := context.Background()

	test := []struct {
		name      string
		projectID string
		zone      string
		instance  string
	}{
		{
			name:      "TestStopInstance",
			projectID: "test-project-id",
			zone:      "test-zone",
			instance:  "test-instance",
		},
	}

	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			h := entities.NewHost(&stubs.ComputeStub{})
			message := map[string]string{"projectID": tt.projectID, "zone": tt.zone, "instance": tt.instance}
			pbMessage := pubsub.Message{Attributes: message}

			if err := StopInstance(ctx, pbMessage, h); err != nil {
				t.Errorf("%s test failed want:%q", tt.name, err)
			}
		})
	}
}
