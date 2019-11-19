package clients

import (
	pagerduty "github.com/PagerDuty/go-pagerduty"
)

// PagerDuty client.
type PagerDuty struct {
	client *pagerduty.Client
}

// NewPagerDuty returns a PagerDuty client initialized.
func NewPagerDuty(apiKey string) *PagerDuty {
	return &PagerDuty{client: pagerduty.NewClient(apiKey)}
}

// CreateIncident will create a new incident.
func (p *PagerDuty) CreateIncident(from, serviceID, title, body string) (*pagerduty.Incident, error) {
	return p.client.CreateIncident(from, &pagerduty.CreateIncidentOptions{
		Type:  "",
		Title: title,
		Service: &pagerduty.APIReference{
			ID:   serviceID,
			Type: "service_reference",
		},
		IncidentKey: "",
		Body: &pagerduty.APIDetails{
			Type:    "incident_body",
			Details: body,
		},
	})
}
