package entities

import (
	"context"
	"fmt"

	"github.com/googlecloudplatform/threat-automation/clients"
)

const (
	authFile = "credentials/auth.json"
)

// Entity holds all initialized entities.
type Entity struct {
	Logger   *Logger
	Resource *Resource
	Host     *Host
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

	return &Entity{
		Host:     host,
		Logger:   log,
		Resource: res,
	}, nil
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
