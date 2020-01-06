package notifyturbinia

import (
	"context"
	"encoding/json"
	"log"

	"cloud.google.com/go/pubsub"
	"github.com/google/uuid"
	"github.com/googlecloudplatform/security-response-automation/services"
)

const turbiniaRequestType = "TurbiniaRequest"

// GoogleCloudDisk represents a GCP disk.
type GoogleCloudDisk struct {
	Project  string `json:"project"`
	Zone     string `json:"zone"`
	DiskName string `json:"disk_name"`
}

// TurbiniaRequest is a request to send to Turbinia.
type TurbiniaRequest struct {
	RequestID string            `json:"request_id"`
	Type      string            `json:"type"`
	Evidence  []GoogleCloudDisk `json:"evidence"`
}

//Services contains the services needed for this function.
type Services struct {
	PubSub *services.PubSub
	Logger *services.Logger
}

//Values contains the required values needed for this function.
type Values struct {
	ProjectID, Topic, Zone, DiskName string
}

// Execute will send the disks to Turbinia.
func Execute(ctx context.Context, values *Values, s *Services) error {
	turbiniaProjectID := values.ProjectID
	topic := values.Topic
	zone := values.Zone
	diskName := values.DiskName
	m := &pubsub.Message{}
	b, err := buildRequest(turbiniaProjectID, zone, diskName)
	if err != nil {
		return err
	}
	m.Data = b
	log.Printf("sending disk %q to Turbinia project %q", diskName, turbiniaProjectID)
	if _, err := s.PubSub.Publish(ctx, topic, m); err != nil {
		return err
	}
	return nil
}

func buildRequest(projectID, zone, diskName string) ([]byte, error) {
	var req TurbiniaRequest
	req.RequestID = uuid.New().String()
	req.Type = turbiniaRequestType
	req.Evidence = []GoogleCloudDisk{
		{
			Project:  projectID,
			Zone:     zone,
			DiskName: diskName,
		},
	}
	return json.Marshal(req)
}
