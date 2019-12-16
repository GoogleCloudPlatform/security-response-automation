package publicsqlinstance

import (
	"encoding/json"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/cloud-sql/removepublic"
	pb "github.com/googlecloudplatform/security-response-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/sha"
)

// Automation defines the configuration for this finding.
type Automation struct {
	Action     string
	Target     []string
	Exclude    []string
	Properties struct {
		DryRun bool `yaml:"dry_run"`
	}
}

// Finding represents this finding.
type Finding struct {
	publicsqlinstance *pb.SqlScanner
}

// Name returns the rule name of the finding.
func (f *Finding) Name(b []byte) string {
	var finding pb.SqlScanner
	if err := json.Unmarshal(b, &finding); err != nil {
		return ""
	}
	return finding.GetFinding().GetCategory()
}

// New returns a new finding.
func New(b []byte) (*Finding, error) {
	var f Finding
	if err := json.Unmarshal(b, &f.publicsqlinstance); err != nil {
		return nil, err
	}
	return &f, nil
}

// RemovePublic returns values for the remove public automation.
func (f *Finding) RemovePublic() *removepublic.Values {
	return &removepublic.Values{
		ProjectID:    f.publicsqlinstance.GetFinding().GetSourceProperties().GetProjectID(),
		InstanceName: sha.Instance(f.publicsqlinstance.GetFinding().GetResourceName()),
	}
}
