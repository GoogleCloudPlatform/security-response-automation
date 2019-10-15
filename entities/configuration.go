package entities

import (
	"encoding/json"
)

// Resources represents common resource IDs used for configuration.
type Resources struct {
	FolderIDs      []string `json:"folder_ids"`
	ProjectIDs     []string `json:"project_ids"`
	OrganizationID string   `json:"organization_id"`
}

// CloseBucket contains configuration required for the Cloud Bucket function.
type CloseBucket struct {
	Resources *Resources
}

// RevokeGrants contains configuration required for the Revoke Grants function.
type RevokeGrants struct {
	Resources  *Resources
	Removelist []string `json:"remove_list"`
}

// Configuration contains the ID(s) to apply actions to.
type Configuration struct {
	CloseBucket  *CloseBucket  `json:"close_bucket"`
	RevokeGrants *RevokeGrants `json:"remove_grants"`
}

// NewConfiguration returns a new configuration.
func NewConfiguration(b []byte) (*Configuration, error) {
	c := &Configuration{}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, err
	}
	return c, nil
}
