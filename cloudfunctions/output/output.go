package output

import (
	"context"
	"encoding/json"
	"errors"
	"log"

	"cloud.google.com/go/pubsub"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/output/channels"
	"github.com/googlecloudplatform/security-response-automation/services"
)

// Configuration maps channels attributes.
type Configuration struct {
	APIVersion string
	Spec       struct {
		Channels struct {
			Turbinia channels.Attributes `yaml:"channels"`
		}
	}
}

// Services contains the services needed for this function.
type Services struct {
	Configuration *Configuration
}

//ChannelMessage contains the required values for this function.
type ChannelMessage struct {
	CorrelationID  string
	Timestamp      string
	AutomationName string
	SourceInfo     string
	Priority       string
	Status         string
	SensitiveInfo  bool
	Subject        string
	Message        string
}

// ChannelRedirect will sent notification to the available channel.
func ChannelRedirect(ctx context.Context, m pubsub.Message) error {
	var values ChannelMessage
	var os Services
	if err := json.Unmarshal(m.Data, &values); err != nil {
		switch values.SourceInfo {
		case "channels":

			log.Printf("received: %+v", values)

			diskName := values.Message
			turbiniaProjectID := os.Configuration.Spec.Channels.Turbinia.ProjectID
			turbiniaTopicName := os.Configuration.Spec.Channels.Turbinia.Topic
			turbiniaZone := os.Configuration.Spec.Channels.Turbinia.Zone
			if err := services.SendTurbinia(ctx, turbiniaProjectID, turbiniaTopicName, turbiniaZone, diskName); err != nil {
				return err
			}
			//svcs.Logger.Info("sent %d disks to channels", len(diskNames))
			log.Printf("sent %q disk to channels", diskName)
		default:
			return err
		}
		return nil
	}
	return errors.New("")
}
