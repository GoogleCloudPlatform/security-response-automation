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

// RemoveNonOrgMembers contains configuration required for remove non-org members function.
type RemoveNonOrgMembers struct {
	Resources    *Resources
	AllowDomains []string `json:"allow_domains"`
	DryRun       bool     `json:"dry_run"`
}

// Configuration contains the ID(s) to apply actions to.
type Configuration struct {
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
