package output

import (
	"context"
	"io/ioutil"
	"log"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/output/channels/turbinia"
	"github.com/googlecloudplatform/security-response-automation/services"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

// Configuration maps channels attributes.
type Configuration struct {
	APIVersion string
	Spec       struct {
		Channels struct {
			Turbinia turbinia.Attributes `yaml:"channels"`
		}
	}
}

// Services contains the services needed for this function.
type Services struct {
	Configuration *Configuration
	Logger        *services.Logger
}

// Config will return the output's configuration.
func Config() (*Configuration, error) {
	var c Configuration
	b, err := ioutil.ReadFile("./cloudfunctions/output/config.yaml")
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
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

// Execute will orchestrate the notification to the available channel.
func Execute(ctx context.Context, c *ChannelMessage, s *Services) error {
	switch c.SourceInfo {
	case "turbinia":

		log.Printf("received: %+v", c)

		diskName := c.Message
		turbiniaProjectID := s.Configuration.Spec.Channels.Turbinia.ProjectID
		turbiniaTopicName := s.Configuration.Spec.Channels.Turbinia.Topic
		turbiniaZone := s.Configuration.Spec.Channels.Turbinia.Zone
		if err := services.SendTurbinia(ctx, turbiniaProjectID, turbiniaTopicName, turbiniaZone, diskName); err != nil {
			return errors.Wrapf(err, "failed while sending Turbinia request to %q on project %q",
				turbiniaTopicName, turbiniaProjectID)
		}
		s.Logger.Info("sent %d disks to channels")
	case "pagerduty":
	case "slack":
	case "sendgrid":
	case "stackdriver":
	default:
		return errors.Errorf("Invalid channel option")
	}
	return nil
}
