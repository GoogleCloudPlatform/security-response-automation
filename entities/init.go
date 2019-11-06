package entities

import (
	"context"
	"fmt"

	"github.com/googlecloudplatform/threat-automation/clients"
)

const (
	authFile     = "credentials/auth.json"
	settingsFile = "settings.json"
)

// Entity holds all initialized entities.
type Entity struct {
	Configuration *Configuration
	Logger        *Logger
	Resource      *Resource
	Host          *Host
	Firewall      *Firewall
	Container     *Container
	CloudSQL      *CloudSQL
	BigQuery      *BigQuery
}

// New returns an initialized Entity struct.
func New(ctx context.Context) (*Entity, error) {
	host, err := initHost(ctx)
	if err != nil {
		return nil, err
	}

	log, err := initLog(ctx)
	if err != nil {
		return nil, err
	}

	res, err := initResource(ctx)
	if err != nil {
		return nil, err
	}

	fw, err := initFirewall(ctx)
	if err != nil {
		return nil, err
	}

	config, err := initConfiguration()
	if err != nil {
		return nil, err
	}

	cont, err := initContainer(ctx)
	if err != nil {
		return nil, err
	}

	sql, err := initCloudSQL(ctx)
	if err != nil {
		return nil, err
	}

	bq, err := initBigQuery(ctx)
	if err != nil {
		return nil, err
	}

	return &Entity{
		Configuration: config,
		Host:          host,
		Logger:        log,
		Resource:      res,
		Firewall:      fw,
		Container:     cont,
		CloudSQL:      sql,
		BigQuery:      bq,
	}, nil
}

func initConfiguration() (*Configuration, error) {
	conf, err := NewConfiguration(settingsFile)
	if err != nil {
		return nil, err
	}
	return conf, nil
}

func initHost(ctx context.Context) (*Host, error) {
	cs, err := clients.NewCompute(ctx, authFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize compute client: %q", err)
	}
	return NewHost(cs), nil
}

func initLog(ctx context.Context) (*Logger, error) {
	logClient, err := clients.NewLogger(ctx, authFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger client: %q", err)
	}
	return NewLogger(logClient), nil
}

func initResource(ctx context.Context) (*Resource, error) {
	crm, err := clients.NewCloudResourceManager(ctx, authFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cloud resource manager client: %q", err)
	}
	stg, err := clients.NewStorage(ctx, authFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage client: %q", err)
	}
	return NewResource(crm, stg), nil
}

func initFirewall(ctx context.Context) (*Firewall, error) {
	cs, err := clients.NewCompute(ctx, authFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize compute client: %q", err)
	}
	return NewFirewall(cs), nil
}

func initContainer(ctx context.Context) (*Container, error) {
	cc, err := clients.NewContainer(ctx, authFile)
	if err != nil {
		return nil, fmt.Errorf("Failed to initialize container client: %q", err)
	}
	return NewContainer(cc), nil
}

func initCloudSQL(ctx context.Context) (*CloudSQL, error) {
	cs, err := clients.NewCloudSQL(ctx, authFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize sql client: %q", err)
	}
	return NewCloudSQL(cs), nil
}

func initBigQuery(ctx context.Context) (*BigQuery, error) {
	bq, err := clients.NewBigQuery(ctx, authFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize bigquery client: %q", err)
	}
	return NewBigQuery(bq), nil
}
