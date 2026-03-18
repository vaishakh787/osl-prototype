package providers

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"

	"github.com/docker/go-plugins-helpers/secrets"
	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
)

// VaultProvider implements the SecretsProvider interface for HashiCorp Vault
type VaultProvider struct {
	client *api.Client
	config *SecretsConfig
}

// SecretsConfig holds the configuration for the Vault client
type SecretsConfig struct {
	Address    string
	Token      string
	MountPath  string
	RoleID     string
	SecretID   string
	AuthMethod string
	CACert     string
	ClientCert string
	ClientKey  string
	SkipVerify bool
	// CABundle is a raw PEM-encoded CA certificate bundle (alternative to CACert file path)
	CABundle string
	// JWTToken is the raw JWT used for jwt/oidc authentication
	JWTToken string
	// OIDCRole is the Vault role to authenticate against when using jwt/oidc auth method
	OIDCRole string
}

// Initialize sets up the Vault provider with the given configuration
func (v *VaultProvider) Initialize(config map[string]string) error {
	v.config = &SecretsConfig{
		Address:    getConfigOrDefault(config, "VAULT_ADDR", ""),
		Token:      getConfigOrDefault(config, "VAULT_TOKEN", ""),
		MountPath:  getConfigOrDefault(config, "VAULT_MOUNT_PATH", "secret"),
		RoleID:     config["VAULT_ROLE_ID"],
		SecretID:   config["VAULT_SECRET_ID"],
		AuthMethod: getConfigOrDefault(config, "VAULT_AUTH_METHOD", "token"),
		CACert:     config["VAULT_CACERT"],
		ClientCert: config["VAULT_CLIENT_CERT"],
		ClientKey:  config["VAULT_CLIENT_KEY"],
		SkipVerify: getConfigOrDefault(config, "VAULT_SKIP_VERIFY", "false") == "true",
		CABundle:   config["VAULT_CA_BUNDLE"],
		JWTToken:   config["VAULT_JWT_TOKEN"],
		OIDCRole:   config["VAULT_OIDC_ROLE"],
	}

	// Configure Vault client
	SecretsConfig := api.DefaultConfig()
	SecretsConfig.Address = v.config.Address

	// If a raw CABundle is provided, parse it and inject into the HTTP client transport.
	// This allows passing PEM content directly rather than a file path.
	if v.config.CABundle != "" {
		tlsCfg, err := BuildTLSConfig(TLSConfig{
			CABundle:   v.config.CABundle,
			ClientCert: v.config.ClientCert,
			ClientKey:  v.config.ClientKey,
			Insecure:   v.config.SkipVerify,
		})
		if err != nil {
			return fmt.Errorf("failed to configure TLS from VAULT_CA_BUNDLE: %w", err)
		}
		SecretsConfig.HttpClient = &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		}
	} else if v.config.CACert != "" || v.config.ClientCert != "" || v.config.SkipVerify {
		// Fall back to file-based TLS config (existing behaviour)
		tlsConfig := &api.TLSConfig{
			CACert:     v.config.CACert,
			ClientCert: v.config.ClientCert,
			ClientKey:  v.config.ClientKey,
			Insecure:   v.config.SkipVerify,
		}
		if err := SecretsConfig.ConfigureTLS(tlsConfig); err != nil {
			return fmt.Errorf("failed to configure TLS: %v", err)
		}
	}

	client, err := api.NewClient(SecretsConfig)
	if err != nil {
		return fmt.Errorf("failed to create vault client: %v", err)
	}

	v.client = client

	// Authenticate with Vault
	if err := v.authenticate(); err != nil {
		return fmt.Errorf("failed to authenticate with vault: %v", err)
	}

	log.Printf("Successfully initialized Vault provider using %s method", v.config.AuthMethod)
	return nil
}

// GetSecret retrieves a secret value from Vault
func (v *VaultProvider) GetSecret(ctx context.Context, req secrets.Request) ([]byte, error) {
	secretPath := v.buildSecretPath(req)
	log.Printf("Reading secret from Vault/OpenBao path: %s", secretPath)

	// Read secret from Vault
	secret, err := v.client.Logical().ReadWithContext(ctx, secretPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret from vault: %v", err)
	}

	if secret == nil {
		return nil, fmt.Errorf("secret not found at path: %s", secretPath)
	}

	// Extract the secret value
	value, err := v.extractSecretValue(secret, req)
	if err != nil {
		return nil, fmt.Errorf("failed to extract secret value: %v", err)
	}

	log.Printf("Successfully retrieved secret from Vault")
	return value, nil
}

// SupportsRotation indicates that Vault supports secret rotation monitoring
func (v *VaultProvider) SupportsRotation() bool {
	return true
}

// CheckSecretChanged checks if a secret has changed in Vault
func (v *VaultProvider) CheckSecretChanged(ctx context.Context, secretInfo *SecretInfo) (bool, error) {
	// Read secret from Vault
	secret, err := v.client.Logical().ReadWithContext(ctx, secretInfo.SecretPath)
	if err != nil {
		return false, fmt.Errorf("error reading secret from vault: %v", err)
	}

	if secret == nil {
		return false, fmt.Errorf("secret not found at path: %s", secretInfo.SecretPath)
	}

	// Extract current value
	var data map[string]interface{}
	if secretData, ok := secret.Data["data"]; ok {
		data = secretData.(map[string]interface{})
	} else {
		data = secret.Data
	}

	var currentValue []byte
	if value, ok := data[secretInfo.SecretField]; ok {
		currentValue = []byte(fmt.Sprintf("%v", value))
	} else {
		return false, fmt.Errorf("field %s not found in secret", secretInfo.SecretField)
	}

	// Calculate current hash
	currentHash := fmt.Sprintf("%x", sha256.Sum256(currentValue))

	return currentHash != secretInfo.LastHash, nil
}

// GetProviderName returns the name of this provider
func (v *VaultProvider) GetProviderName() string {
	return "vault"
}

// Close performs cleanup for the Vault provider
func (v *VaultProvider) Close() error {
	// Vault client doesn't require explicit cleanup
	return nil
}

// authenticate handles various Vault authentication methods
func (v *VaultProvider) authenticate() error {
	switch v.config.AuthMethod {
	case "token":
		if v.config.Token == "" {
			return fmt.Errorf("VAULT_TOKEN is required for token authentication")
		}
		v.client.SetToken(v.config.Token)

	case "approle":
		if v.config.RoleID == "" || v.config.SecretID == "" {
			return fmt.Errorf("VAULT_ROLE_ID and VAULT_SECRET_ID are required for approle authentication")
		}

		data := map[string]interface{}{
			"role_id":   v.config.RoleID,
			"secret_id": v.config.SecretID,
		}

		resp, err := v.client.Logical().Write("auth/approle/login", data)
		if err != nil {
			return fmt.Errorf("approle authentication failed: %v", err)
		}

		if resp.Auth == nil {
			return fmt.Errorf("no auth info returned from approle login")
		}

		v.client.SetToken(resp.Auth.ClientToken)

	case "jwt", "oidc":
		// JWT/OIDC authentication
		// https://developer.hashicorp.com/vault/docs/auth/jwt
		if v.config.JWTToken == "" {
			return fmt.Errorf("VAULT_JWT_TOKEN is required for %s authentication", v.config.AuthMethod)
		}
		if v.config.OIDCRole == "" {
			return fmt.Errorf("VAULT_OIDC_ROLE is required for %s authentication", v.config.AuthMethod)
		}

		data := map[string]interface{}{
			"jwt":  v.config.JWTToken,
			"role": v.config.OIDCRole,
		}

		loginPath := fmt.Sprintf("auth/%s/login", v.config.AuthMethod)
		resp, err := v.client.Logical().Write(loginPath, data)
		if err != nil {
			return fmt.Errorf("%s authentication failed: %v", v.config.AuthMethod, err)
		}

		if resp == nil || resp.Auth == nil {
			return fmt.Errorf("no auth info returned from %s login", v.config.AuthMethod)
		}

		v.client.SetToken(resp.Auth.ClientToken)
		log.Printf("Successfully authenticated with Vault using %s method (role: %s)",
			v.config.AuthMethod, v.config.OIDCRole)

	default:
		return fmt.Errorf("unsupported authentication method: %s", v.config.AuthMethod)
	}

	return nil
}

// buildSecretPath constructs the Vault secret path based on request labels and service information
func (v *VaultProvider) buildSecretPath(req secrets.Request) string {
	// Use custom path from labels if provided
	if customPath, exists := req.SecretLabels["vault_path"]; exists {
		// For KV v2, ensure we have the /data/ prefix
		if v.config.MountPath == "secret" {
			return fmt.Sprintf("%s/data/%s", v.config.MountPath, customPath)
		}
		return fmt.Sprintf("%s/%s", v.config.MountPath, customPath)
	}

	// Default path structure for KV v2
	if v.config.MountPath == "secret" {
		if req.ServiceName != "" {
			return fmt.Sprintf("%s/data/%s/%s", v.config.MountPath, req.ServiceName, req.SecretName)
		}
		return fmt.Sprintf("%s/data/%s", v.config.MountPath, req.SecretName)
	}

	// For other mount paths
	if req.ServiceName != "" {
		return fmt.Sprintf("%s/%s/%s", v.config.MountPath, req.ServiceName, req.SecretName)
	}
	return fmt.Sprintf("%s/%s", v.config.MountPath, req.SecretName)
}

// extractSecretValue extracts the appropriate value from the Vault response
func (v *VaultProvider) extractSecretValue(secret *api.Secret, req secrets.Request) ([]byte, error) {
	// For KV v2, data is nested under "data"
	var data map[string]interface{}
	if secretData, ok := secret.Data["data"]; ok {
		data = secretData.(map[string]interface{})
	} else {
		data = secret.Data
	}

	// Check for specific field in labels
	if field, exists := req.SecretLabels["vault_field"]; exists {
		if value, ok := data[field]; ok {
			return []byte(fmt.Sprintf("%v", value)), nil
		}
		return nil, fmt.Errorf("field %s not found in secret", field)
	}

	// Default field names to try
	defaultFields := []string{"value", "password", "secret", "data"}

	// Try to find a value using default field names
	for _, field := range defaultFields {
		if value, ok := data[field]; ok {
			return []byte(fmt.Sprintf("%v", value)), nil
		}
	}

	// If no specific field found, return the first string value
	for _, value := range data {
		if strValue, ok := value.(string); ok {
			return []byte(strValue), nil
		}
	}

	return nil, fmt.Errorf("no suitable secret value found")
}

// getConfigOrDefault returns config value or environment variable or default
func getConfigOrDefault(config map[string]string, key, defaultValue string) string {
	if value, exists := config[key]; exists && value != "" {
		return value
	}
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
