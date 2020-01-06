package turbinia

// Attributes are requirements for Turbinia configuration.
type Attributes struct {
	ProjectID string `yaml:"project_id"`
	Topic     string
	Zone      string
}
