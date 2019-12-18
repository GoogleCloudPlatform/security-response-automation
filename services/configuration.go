package services

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

// Resources represents common resource IDs used for configuration.
type Resources struct {
	FolderIDs      []string `json:"folder_ids"`
	ProjectIDs     []string `json:"project_ids"`
	OrganizationID string   `json:"organization_id"`
}

// ClosePublicDataset contains configuration required for the close public dataset function.
type ClosePublicDataset struct {
	Resources *Resources
	DryRun    bool `json:"dry_run"`
}

// EnableAuditLogs configuration required to enable data access audit logs
type EnableAuditLogs struct {
	Resources *Resources
	DryRun    bool `json:"dry_run"`
}

// DisableDashboard contains configuration required for the disable dashboard function.
type DisableDashboard struct {
	Resources *Resources
	DryRun    bool `json:"dry_run"`
}

// RemoveNonOrgMembers contains configuration required for remove non-org members function.
type RemoveNonOrgMembers struct {
	Resources    *Resources
	AllowDomains []string `json:"allow_domains"`
	DryRun       bool     `json:"dry_run"`
}

// Configuration contains the ID(s) to apply actions to.
type Configuration struct {
	ClosePublicDataset  *ClosePublicDataset  `json:"close_public_dataset"`
	DisableDashboard    *DisableDashboard    `json:"disable_dashboard"`
	EnableAuditLogs     *EnableAuditLogs     `json:"enable_audit_logs"`
	RemoveNonOrgMembers *RemoveNonOrgMembers `json:"remove_non_org_members"`
}

// NewConfiguration returns a new configuration.
func NewConfiguration(file string) (*Configuration, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	c := &Configuration{}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, err
	}
	return c, nil
}
