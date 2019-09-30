package cloudfunctions

import (
	"context"
	"fmt"

	"cloud.google.com/go/pubsub"
	"github.com/googlecloudplatform/threat-automation/entities"
)

//StopInstance stops gce instance
func StopInstance(ctx context.Context, m pubsub.Message, h *entities.Host) error {

	//TODO change to use pubsub.Message to set those vars
	project := "my-project"
	zone := "my-zone"
	instance := "my-instance"

	resp, err := h.StopComputeInstance(ctx, project, zone, instance)
	if err != nil {
		return err
	}

	fmt.Printf("%#v\n instance call stop:", resp)
	return nil
}
