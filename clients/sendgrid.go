package clients

import (
	"fmt"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

const (
	// Sender name email
	Sender = "Security Response Automation"
)

// SendGrid client.
type SendGrid struct {
	senderName string
	service    *sendgrid.Client
}

// EmailResponse email response data
type EmailResponse struct {
	StatusCode int
	Body       string
}

// NewSendGridClient returns and initializes the SendGrid client.
func NewSendGridClient(apiKey string) *SendGrid {
	return &SendGrid{
		service:    sendgrid.NewSendClient(apiKey),
		senderName: Sender,
	}
}

// Send email SendGrid.
func (s *SendGrid) Send(subject, from, body string, to []string) (*EmailResponse, error) {
	e := createEmail(subject, from, body, s.senderName, to)
	r, err := s.service.Send(e)

	if err != nil {
		return nil, err
	}

	if r.StatusCode < 200 || r.StatusCode > 202 {
		return nil, fmt.Errorf("Error to send email. StatusCode:(%d)", r.StatusCode)
	}

	return &EmailResponse{StatusCode: r.StatusCode, Body: r.Body}, err
}

func createEmail(subject, from, body, sender string, to []string) *mail.SGMailV3 {
	email := mail.NewV3Mail()
	email.SetFrom(mail.NewEmail(sender, from))
	email.Subject = subject

	p := mail.NewPersonalization()
	for _, e := range to {
		p.AddTos(mail.NewEmail(e, e))
	}
	email.AddContent(mail.NewContent("text/plain", body))
	email.AddPersonalizations(p)
	return email
}
