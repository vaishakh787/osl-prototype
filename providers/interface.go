package providers

import (
	"context"
	"time"

	"github.com/docker/go-plugins-helpers/secrets"
)

type SecretInfo struct {
	DockerSecretName string
	SecretPath       string
	SecretField      string
	ServiceNames     []string
	LastHash         string
	LastUpdated      time.Time
	Provider         string
}

type SecretsProvider interface {
	Initialize(config map[string]string) error
	GetSecret(ctx context.Context, req secrets.Request) ([]byte, error)
	SupportsRotation() bool
	CheckSecretChanged(ctx context.Context, secretInfo *SecretInfo) (bool, error)
	GetProviderName() string
	Close() error
}
