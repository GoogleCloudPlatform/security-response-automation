package loggingscanner

import (
	"encoding/json"
	"strings"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/iam/enableauditlogs"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/sha/protos"
)

// Finding represents this finding.
type Finding struct {
	Loggingscanner *pb.LoggingScanner
}

// New returns a new finding.
func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.Loggingscanner); err != nil {
		return nil, err
	}
	return &f, nil
}

// Name returns the category of the finding.
func (f *Finding) Name(b []byte) string {
	var finding pb.LoggingScanner
	if err := json.Unmarshal(b, &finding); err != nil {
		return ""
	}
	if finding.GetFinding().GetSourceProperties().GetScannerName() != "LOGGING_SCANNER" {
		return ""
	}
	return strings.ToLower(finding.GetFinding().GetCategory())
}

// EnableAuditLogs return values for the enable audit logs automation.
func (f *Finding) EnableAuditLogs() *enableauditlogs.Values {
	return &enableauditlogs.Values{
		ProjectID: f.Loggingscanner.GetFinding().GetSourceProperties().GetProjectID(),
	}
}
