package clients

import (
	"log"

	pagerduty "github.com/PagerDuty/go-pagerduty"
	"github.com/googlecloudplatform/security-response-automation/services/mode"
)

// PagerDuty client.
type PagerDuty struct {
	client *pagerduty.Client

	// from is the email address of the user creating the incident.
	from string
	// serviceID is the ID of the affected PagerDuty service.
	// - https://support.pagerduty.com/docs/services-and-integrations
	serviceID string
}

// NewPagerDuty returns a PagerDuty client initialized.
func NewPagerDuty(apiKey, serviceID, from string) *PagerDuty {
	return &PagerDuty{
		client:    pagerduty.NewClient(apiKey),
		from:      from,
		serviceID: serviceID,
	}
}

// SetFrom sets the from email address.
func (p *PagerDuty) SetFrom(from string) { p.from = from }

// SetServiceID sets the affected service ID.
func (p *PagerDuty) SetServiceID(serviceID string) { p.serviceID = serviceID }

// CreateIncident will create a new incident.
func (p *PagerDuty) CreateIncident(title, body string) (*pagerduty.Incident, error) {
	incident := &pagerduty.CreateIncidentOptions{
		Type:  "",
		Title: title,
		Service: &pagerduty.APIReference{
			ID:   p.serviceID,
			Type: "service_reference",
		},
		IncidentKey: "",
		Body: &pagerduty.APIDetails{
			Type:    "incident_body",
			Details: body,
		},
	}
	if mode.DryRun() {
		log.Println("[DRY_RUN] create incident ", incident)
		return nil, nil
	}
	return p.client.CreateIncident(p.from, incident)
}
