package providers

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
)

// VaultProvider implements PushSecretProvider — it supports writing secrets back to Vault.

// SupportsPush indicates that Vault supports bidirectional secret sync.
func (v *VaultProvider) SupportsPush() bool {
	return true
}

// PushSecret writes a secret value to HashiCorp Vault.
// It uses the KV v2 engine by default.
//
// Labels used:
//   push_path  - the Vault path to write to (e.g. "database/mysql")
//   push_field - the field key within the secret (e.g. "password")
func (v *VaultProvider) PushSecret(ctx context.Context, req PushSecretRequest) (PushSecretResponse, error) {
	// Build the full KV v2 write path
	writePath := fmt.Sprintf("%s/data/%s", v.config.MountPath, req.RemotePath)

	log.Infof("Pushing secret '%s' to Vault path: %s (field: %s)",
		req.SecretName, writePath, req.RemoteField)

	field := req.RemoteField
	if field == "" {
		field = "value"
	}

	// KV v2 write format: {"data": {"field": "value"}}
	data := map[string]interface{}{
		"data": map[string]interface{}{
			field: string(req.SecretValue),
		},
	}

	resp, err := v.client.Logical().WriteWithContext(ctx, writePath, data)
	if err != nil {
		return PushSecretResponse{}, fmt.Errorf("failed to push secret to Vault path '%s': %w", writePath, err)
	}

	version := ""
	if resp != nil && resp.Data != nil {
		if meta, ok := resp.Data["version"]; ok {
			version = fmt.Sprintf("%v", meta)
		}
	}

	log.Infof("Successfully pushed secret '%s' to Vault (version: %s)", req.SecretName, version)
	return PushSecretResponse{
		RemotePath: writePath,
		Version:    version,
	}, nil
}

// DeleteSecret removes a secret from HashiCorp Vault.
func (v *VaultProvider) DeleteSecret(ctx context.Context, req DeleteSecretRequest) error {
	// KV v2 metadata delete path removes all versions
	deletePath := fmt.Sprintf("%s/metadata/%s", v.config.MountPath, req.RemotePath)

	log.Infof("Deleting secret at Vault path: %s", deletePath)

	_, err := v.client.Logical().DeleteWithContext(ctx, deletePath)
	if err != nil {
		return fmt.Errorf("failed to delete secret at Vault path '%s': %w", deletePath, err)
	}

	log.Infof("Successfully deleted secret at Vault path: %s", deletePath)
	return nil
}
