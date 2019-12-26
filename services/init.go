package services

import (
	"context"

	"github.com/googlecloudplatform/security-response-automation/clients"
	"github.com/pkg/errors"
)

const (
	authFile = "credentials/auth.json"
)

// Global holds all initialized services.
type Global struct {
	Logger    *Logger
	Resource  *Resource
	Host      *Host
	Firewall  *Firewall
	Container *Container
	CloudSQL  *CloudSQL
}

// New returns an initialized Global struct.
func New(ctx context.Context) (*Global, error) {
	host, err := initHost(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize Host service")
	}

	log, err := initLog(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize Logger service")
	}

	res, err := initResource(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize Resource service")
	}

	fw, err := initFirewall(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize Firewall service")
	}

	cont, err := initContainer(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize Container service")
	}

	sql, err := initCloudSQL(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize Cloud SQL service")
	}

	return &Global{
		Host:      host,
		Logger:    log,
		Resource:  res,
		Firewall:  fw,
		Container: cont,
		CloudSQL:  sql,
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
		return nil, errors.Wrapf(err, "failed to initialize BigQuery client on: %q", projectID)
	}
	return NewBigQuery(bq), nil
}

// InitPubSub creates and initializes a new instance of PubSub.
func InitPubSub(ctx context.Context, projectID string) (*PubSub, error) {
	pubsub, err := clients.NewPubSub(ctx, authFile, projectID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to initialize PubSub client on: %q", projectID)
	}
	return NewPubSub(pubsub), nil
}

func initHost(ctx context.Context) (*Host, error) {
	cs, err := clients.NewCompute(ctx, authFile)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize compute client")
	}
	return NewHost(cs), nil
}

func initLog(ctx context.Context) (*Logger, error) {
	logClient, err := clients.NewLogger(ctx, authFile)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize logger client")
	}
	return NewLogger(logClient), nil
}

func initResource(ctx context.Context) (*Resource, error) {
	crm, err := clients.NewCloudResourceManager(ctx, authFile)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize cloud resource manager client")
	}
	stg, err := clients.NewStorage(ctx, authFile)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize storage client")
	}
	return NewResource(crm, stg), nil
}

func initFirewall(ctx context.Context) (*Firewall, error) {
	cs, err := clients.NewCompute(ctx, authFile)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize compute client")
	}
	return NewFirewall(cs), nil
}

func initContainer(ctx context.Context) (*Container, error) {
	cc, err := clients.NewContainer(ctx, authFile)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize container client")
	}
	return NewContainer(cc), nil
}

func initCloudSQL(ctx context.Context) (*CloudSQL, error) {
	cs, err := clients.NewCloudSQL(ctx, authFile)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize sql client")
	}
	return NewCloudSQL(cs), nil
}
