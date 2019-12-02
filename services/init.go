package services

import (
	"context"
	"fmt"

	"github.com/googlecloudplatform/security-response-automation/clients"
	"github.com/googlecloudplatform/security-response-automation/clients/dryrun"
)

const (
	authFile     = "credentials/auth.json"
	settingsFile = "settings.json"
)

// Global holds all initialized services.
type Global struct {
	Configuration *Configuration
	Logger        *Logger
	Resource      *Resource
	Host          *Host
	Firewall      *Firewall
	Container     *Container
	CloudSQL      *CloudSQL
}

// DryRun returns a initialized Global struct using the Dry Run implementation
func DryRun(ctx context.Context, original *Global) (*Global, error) {

	host, err := initDryRunHost(ctx)
	if err != nil {
		return nil, err
	}

	fw, err := initDryRunFirewall(ctx)
	if err != nil {
		return nil, err
	}

	res, err := initDryRunResource(ctx)
	if err != nil {
		return nil, err
	}

	cont, err := initDryRunContainer(ctx)
	if err != nil {
		return nil, err
	}

	sql, err := initDryRunCloudSQL(ctx)
	if err != nil {
		return nil, err
	}

	return &Global{
		Configuration: original.Configuration,
		Host:          host,
		Logger:        original.Logger,
		Resource:      res,
		Firewall:      fw,
		Container:     cont,
		CloudSQL:      sql,
	}, nil
}

// New returns an initialized Global struct.
func New(ctx context.Context) (*Global, error) {
	config, err := initConfiguration()
	if err != nil {
		return nil, err
	}

	log, err := initLog(ctx)
	if err != nil {
		return nil, err
	}

	host, err := initHost(ctx)
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

	cont, err := initContainer(ctx)
	if err != nil {
		return nil, err
	}

	sql, err := initCloudSQL(ctx)
	if err != nil {
		return nil, err
	}

	return &Global{
		Configuration: config,
		Host:          host,
		Logger:        log,
		Resource:      res,
		Firewall:      fw,
		Container:     cont,
		CloudSQL:      sql,
	}, nil
}

// InitPagerDuty creates and initializes a new instance of PagerDuty.
func InitPagerDuty(apiKey string) *PagerDuty {
	pd := clients.NewPagerDuty(apiKey)
	return NewPagerDuty(pd)
}

// InitBigQuery creates and initializes a new instance of BigQuery.
func InitBigQuery(ctx context.Context, projectID string) (*BigQuery, error) {
	bq, err := clients.NewBigQuery(ctx, authFile, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize bigquery client: %q", err)
	}
	return NewBigQuery(bq), nil
}

// InitDryRunBigQuery creates and initializes a new instance of BigQuery.
func InitDryRunBigQuery(ctx context.Context, projectID string) (*BigQuery, error) {
	bqReal, err := clients.NewBigQuery(ctx, authFile, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize bigquery client: %q", err)
	}
	bq, _ := dryrun.NewDryRunBigQuery(bqReal)
	return NewBigQuery(bq), nil
}

// InitPubSub creates and initializes a new instance of PubSub.
func InitPubSub(ctx context.Context, projectID string) (*PubSub, error) {
	pubsub, err := clients.NewPubSub(ctx, authFile, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize pubsub client: %q", err)
	}
	return NewPubSub(pubsub), nil
}

func initConfiguration() (*Configuration, error) {
	conf, err := NewConfiguration(settingsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration: %q", err)
	}
	return conf, nil
}

func initLog(ctx context.Context) (*Logger, error) {
	logClient, err := clients.NewLogger(ctx, authFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger client: %q", err)
	}
	return NewLogger(logClient), nil
}

func initHost(ctx context.Context) (*Host, error) {
	cs, err := clients.NewCompute(ctx, authFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize compute client: %q", err)
	}
	return NewHost(cs), nil
}

func initDryRunHost(ctx context.Context) (*Host, error) {
	csReal, err := clients.NewCompute(ctx, authFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize compute client: %q", err)
	}
	cs, _ := dryrun.NewDryRunCompute(csReal)
	return NewHost(cs), nil
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

func initDryRunResource(ctx context.Context) (*Resource, error) {
	crmReal, err := clients.NewCloudResourceManager(ctx, authFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cloud resource manager client: %q", err)
	}
	stgReal, err := clients.NewStorage(ctx, authFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage client: %q", err)
	}

	crm, _ := dryrun.NewDryRunCloudResourceManager(crmReal)

	stg, _ := dryrun.NewDryRunStorage(stgReal)

	return NewResource(crm, stg), nil
}

func initFirewall(ctx context.Context) (*Firewall, error) {
	cs, err := clients.NewCompute(ctx, authFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize compute client: %q", err)
	}
	return NewFirewall(cs), nil
}

func initDryRunFirewall(ctx context.Context) (*Firewall, error) {
	csReal, err := clients.NewCompute(ctx, authFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize compute client: %q", err)
	}
	cs, _ := dryrun.NewDryRunCompute(csReal)
	return NewFirewall(cs), nil
}

func initContainer(ctx context.Context) (*Container, error) {
	cc, err := clients.NewContainer(ctx, authFile)
	if err != nil {
		return nil, fmt.Errorf("Failed to initialize container client: %q", err)
	}
	return NewContainer(cc), nil
}

func initDryRunContainer(ctx context.Context) (*Container, error) {
	ccReal, err := clients.NewContainer(ctx, authFile)
	if err != nil {
		return nil, fmt.Errorf("Failed to initialize container client: %q", err)
	}
	cc, _ := dryrun.NewDryRunContainer(ccReal)
	return NewContainer(cc), nil
}

func initCloudSQL(ctx context.Context) (*CloudSQL, error) {
	cs, err := clients.NewCloudSQL(ctx, authFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize sql client: %q", err)
	}
	return NewCloudSQL(cs), nil
}

func initDryRunCloudSQL(ctx context.Context) (*CloudSQL, error) {
	csReal, err := clients.NewCloudSQL(ctx, authFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize sql client: %q", err)
	}
	cs, _ := dryrun.NewDryRunCloudSQL(csReal)
	return NewCloudSQL(cs), nil
}
