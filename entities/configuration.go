package entities

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

// CloseBucket contains configuration required for the Cloud Bucket function.
type CloseBucket struct {
	Resources *Resources
}

type DisableFirewall struct {
	Resources *Resources
}

// RevokeGrants contains configuration required for the Revoke Grants function.
type RevokeGrants struct {
	Resources  *Resources
	Removelist []string `json:"remove_list"`
}

// Configuration contains the ID(s) to apply actions to.
type Configuration struct {
	CloseBucket     *CloseBucket     `json:"close_bucket"`
	RevokeGrants    *RevokeGrants    `json:"revoke_grants"`
	DisableFirewall *DisableFirewall `json:"disable_firewall"`
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
