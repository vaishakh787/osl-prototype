package providers

import (
	"context"
	"fmt"

	"github.com/docker/go-plugins-helpers/secrets"
)

// PushSecretRequest holds the data needed to push a secret to an external provider.
// This enables bidirectional sync — from Docker Swarm outward to the secret backend.
type PushSecretRequest struct {
	// SecretName is the Docker Swarm secret name
	SecretName string
	// SecretValue is the secret value to push
	SecretValue []byte
	// Labels are the Docker secret labels (used to determine path, field, etc.)
	Labels map[string]string
	// RemotePath is the provider-specific path to write the secret to
	RemotePath string
	// RemoteField is the field key within the secret (for JSON-based providers)
	RemoteField string
}

// PushSecretResponse holds the result of a push operation.
type PushSecretResponse struct {
	// RemotePath is the full path where the secret was written
	RemotePath string
	// Version is the version identifier returned by the provider (if supported)
	Version string
}

// DeleteSecretRequest holds the data needed to delete a secret from an external provider.
type DeleteSecretRequest struct {
	// RemotePath is the provider-specific path of the secret to delete
	RemotePath string
	// Labels are the Docker secret labels
	Labels map[string]string
}

// PushSecretProvider extends SecretsProvider with bidirectional sync capability.
// Providers that support writing secrets back to the external backend implement this interface.
//
// This mirrors the PushSecret concept from the Kubernetes external-secrets operator:
// https://external-secrets.io/latest/api/pushsecret/
type PushSecretProvider interface {
	SecretsProvider

	// PushSecret writes a secret value to the external provider.
	// This enables Docker Swarm secrets to be synced outward to the backend.
	PushSecret(ctx context.Context, req PushSecretRequest) (PushSecretResponse, error)

	// DeleteSecret removes a secret from the external provider.
	// Used during reconciliation when a Docker secret is removed.
	DeleteSecret(ctx context.Context, req DeleteSecretRequest) error

	// SupportsPush indicates whether this provider supports writing secrets.
	SupportsPush() bool
}

// PushSecretReconciler manages the reconciliation loop for PushSecret operations.
// It detects changes in Docker Swarm secrets and propagates them to external providers.
type PushSecretReconciler struct {
	provider PushSecretProvider
}

// NewPushSecretReconciler creates a new reconciler for the given provider.
func NewPushSecretReconciler(provider PushSecretProvider) (*PushSecretReconciler, error) {
	if !provider.SupportsPush() {
		return nil, fmt.Errorf("provider %s does not support PushSecret", provider.GetProviderName())
	}
	return &PushSecretReconciler{provider: provider}, nil
}

// Reconcile compares the current Docker secret value with the remote provider value
// and pushes an update if they differ.
func (r *PushSecretReconciler) Reconcile(ctx context.Context, req secrets.Request, value []byte) error {
	pushReq := PushSecretRequest{
		SecretName:  req.SecretName,
		SecretValue: value,
		Labels:      req.SecretLabels,
		RemotePath:  req.SecretLabels["push_path"],
		RemoteField: req.SecretLabels["push_field"],
	}

	if pushReq.RemotePath == "" {
		return fmt.Errorf("push_path label is required for PushSecret")
	}

	_, err := r.provider.PushSecret(ctx, pushReq)
	return err
}
