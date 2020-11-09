package services

import (
	"context"
	"fmt"

	"github.com/googlecloudplatform/security-response-automation/clients"
)

// Global holds all initialized services.
type Global struct {
	Logger                *Logger
	Resource              *Resource
	Host                  *Host
	Firewall              *Firewall
	Container             *Container
	CloudSQL              *CloudSQL
	SecurityCommandCenter *CommandCenter
}

// New returns an initialized Global struct.
func New(ctx context.Context) (*Global, error) {
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

	cont, err := initContainer(ctx)
	if err != nil {
		return nil, err
	}

	sql, err := initCloudSQL(ctx)
	if err != nil {
		return nil, err
	}

	scc, err := initSecurityCommandCenter(ctx)
	if err != nil {
		return nil, err
	}

	return &Global{
		Host:                  host,
		Logger:                log,
		Resource:              res,
		Firewall:              fw,
		Container:             cont,
		CloudSQL:              sql,
		SecurityCommandCenter: scc,
	}, nil
}

// InitPagerDuty creates and initializes a new instance of PagerDuty.
func InitPagerDuty(apiKey string) *PagerDuty {
	pd := clients.NewPagerDuty(apiKey)
	return NewPagerDuty(pd)
}

// InitBigQuery creates and initializes a new instance of BigQuery.
func InitBigQuery(ctx context.Context, projectID string) (*BigQuery, error) {
	bq, err := clients.NewBigQuery(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize bigquery client: %q", err)
	}
	return NewBigQuery(bq), nil
}

// InitPubSub creates and initializes a new instance of PubSub.
func InitPubSub(ctx context.Context, projectID string) (*PubSub, error) {
	pubsub, err := clients.NewPubSub(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize pubsub client: %q", err)
	}
	return NewPubSub(pubsub), nil
}

func initHost(ctx context.Context) (*Host, error) {
	cs, err := clients.NewCompute(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize compute client: %q", err)
	}
	return NewHost(cs), nil
}

func initLog(ctx context.Context) (*Logger, error) {
	logClient, err := clients.NewLogger(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger client: %q", err)
	}
	return NewLogger(logClient), nil
}

func initResource(ctx context.Context) (*Resource, error) {
	crm, err := clients.NewCloudResourceManager(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cloud resource manager client: %q", err)
	}
	stg, err := clients.NewStorage(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage client: %q", err)
	}
	return NewResource(crm, stg), nil
}

func initFirewall(ctx context.Context) (*Firewall, error) {
	cs, err := clients.NewCompute(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize compute client: %q", err)
	}
	return NewFirewall(cs), nil
}

func initContainer(ctx context.Context) (*Container, error) {
	cc, err := clients.NewContainer(ctx)
	if err != nil {
		return nil, fmt.Errorf("Failed to initialize container client: %q", err)
	}
	return NewContainer(cc), nil
}

func initCloudSQL(ctx context.Context) (*CloudSQL, error) {
	cs, err := clients.NewCloudSQL(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize sql client: %q", err)
	}
	return NewCloudSQL(cs), nil
}

func initSecurityCommandCenter(ctx context.Context) (*CommandCenter, error) {
	scc, err := clients.NewSecurityCommandCenter(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize scc client: %q", err)
	}
	return NewCommandCenter(scc), nil
}
