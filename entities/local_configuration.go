package entities

import (
	"encoding/json"
	"io"
	"io/ioutil"
)

// Configuration contains the ID(s) to apply actions to.
type LocalConfiguration struct {
	FoldersIDs     []string
	ProjectIDs     []string
	OrganizationID string
	Removelist     []string
}

// NewConfiguration returns a new configuration.
func NewLocalConfiguration() (*Configuration, error) {
	return &LocalConfiguration{}, nil
}

// Valid returns if the configuration has at least something filled out.
func (c *Configuration) Valid() bool {
	return len(c.FoldersIDs) > 0 || len(c.ProjectIDs) > 0 || c.OrganizationID != ""
}
