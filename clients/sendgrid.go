package clients

import (
	"github.com/sendgrid/rest"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

// SendGrid client.
type SendGrid struct {
	service *sendgrid.Client
}

// NewSendGridClient returns and initializes the SendGrid client.
func NewSendGridClient(apiKey string) *SendGrid {
	return &SendGrid{service: sendgrid.NewSendClient(apiKey)}
}

// Send email SendGrid.
func (s *SendGrid) Send(email *mail.SGMailV3) (*rest.Response, error) {
	return s.service.Send(email)
}
