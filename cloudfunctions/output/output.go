package output

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"log"

	"cloud.google.com/go/pubsub"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/output/notifyturbinia"
	"github.com/googlecloudplatform/security-response-automation/providers/channels/turbinia"
	"github.com/googlecloudplatform/security-response-automation/services"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

var topics = map[string]struct{ Topic string }{
	"turbinia": {Topic: "notify-channel-turbinia"},
}

// Configuration maps channels attributes.
type Configuration struct {
	APIVersion string
	Spec       struct {
		Channels struct {
			Turbinia turbinia.Attributes `yaml:"turbinia"`
		}
	}
}

// Services contains the services needed for this function.
type Services struct {
	Configuration *Configuration
	Logger        *services.Logger
	PubSub        *services.PubSub
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
		log.Printf("executing output %q", c.SourceInfo)
		values := &notifyturbinia.Values{
			ProjectID: s.Configuration.Spec.Channels.Turbinia.ProjectID,
			Topic:     s.Configuration.Spec.Channels.Turbinia.Topic,
			Zone:      s.Configuration.Spec.Channels.Turbinia.Zone,
			DiskName:  c.Message,
		}
		if values.ProjectID == "" || values.Topic == "" || values.Zone == "" {
			return errors.New("missing Turbinia config values")
		}
		topic := topics[c.SourceInfo].Topic
		b, err := json.Marshal(&values)
		if err != nil {
			return err
		}
		if _, err := s.PubSub.Publish(ctx, topic, &pubsub.Message{
			Data: b,
		}); err != nil {
			s.Logger.Error("failed to publish to %q for channel %q", topic, c.SourceInfo)
			return err
		}
		log.Printf("sent to pubsub topic: %q", topic)
	case "pagerduty":
	case "slack":
	case "sendgrid":
	case "stackdriver":
	default:
		return errors.Errorf("Invalid channel option")
	}
	return nil
}
