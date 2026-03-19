package providers

import (
	"context"
	"crypto/sha256"
	"fmt"

	"net/http"

	"github.com/docker/go-plugins-helpers/secrets"
	"github.com/openbao/openbao/api/v2"
	log "github.com/sirupsen/logrus"
)

// OpenBaoProvider implements the SecretsProvider interface for OpenBao
// OpenBao is Vault-compatible, so we can reuse most of the Vault logic
type OpenBaoProvider struct {
	client *api.Client
	config *OpenBaoConfig
}

// OpenBaoConfig holds the configuration for the OpenBao client
type OpenBaoConfig struct {
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
	// OIDCRole is the OpenBao role to authenticate against when using jwt/oidc auth method
	OIDCRole string
}

// Initialize sets up the OpenBao provider with the given configuration
func (o *OpenBaoProvider) Initialize(config map[string]string) error {
	o.config = &OpenBaoConfig{
		Address:    getConfigOrDefault(config, "OPENBAO_ADDR", "http://localhost:8200"),
		Token:      config["OPENBAO_TOKEN"],
		MountPath:  getConfigOrDefault(config, "OPENBAO_MOUNT_PATH", "secret"),
		RoleID:     config["OPENBAO_ROLE_ID"],
		SecretID:   config["OPENBAO_SECRET_ID"],
		AuthMethod: getConfigOrDefault(config, "OPENBAO_AUTH_METHOD", "token"),
		CACert:     config["OPENBAO_CACERT"],
		ClientCert: config["OPENBAO_CLIENT_CERT"],
		ClientKey:  config["OPENBAO_CLIENT_KEY"],
		SkipVerify: getConfigOrDefault(config, "OPENBAO_SKIP_VERIFY", "false") == "true",
		CABundle:   config["OPENBAO_CA_BUNDLE"],
		JWTToken:   config["OPENBAO_JWT_TOKEN"],
		OIDCRole:   config["OPENBAO_OIDC_ROLE"],
	}

	// Configure OpenBao client (using OpenBao API client since OpenBao is compatible)
	openBaoConfig := api.DefaultConfig()
	openBaoConfig.Address = o.config.Address

	// Configure TLS if certificates are provided or verification is skipped
	// If a raw CABundle is provided, parse it and inject into the HTTP client transport
	if o.config.CABundle != "" {
		tlsCfg, err := BuildTLSConfig(TLSConfig{
			CABundle:   o.config.CABundle,
			ClientCert: o.config.ClientCert,
			ClientKey:  o.config.ClientKey,
			Insecure:   o.config.SkipVerify,
		})
		if err != nil {
			return fmt.Errorf("failed to configure TLS from OPENBAO_CA_BUNDLE: %w", err)
		}
		openBaoConfig.HttpClient = &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		}
	} else if o.config.CACert != "" || o.config.ClientCert != "" || o.config.SkipVerify {
		tlsConfig := &api.TLSConfig{
			CACert:     o.config.CACert,
			ClientCert: o.config.ClientCert,
			ClientKey:  o.config.ClientKey,
			Insecure:   o.config.SkipVerify,
		}
		if err := openBaoConfig.ConfigureTLS(tlsConfig); err != nil {
			return fmt.Errorf("failed to configure TLS: %v", err)
		}
	}

	client, err := api.NewClient(openBaoConfig)
	if err != nil {
		return fmt.Errorf("failed to create OpenBao client: %v", err)
	}

	o.client = client

	// Authenticate with OpenBao
	if err := o.authenticate(); err != nil {
		return fmt.Errorf("failed to authenticate with OpenBao: %v", err)
	}

	log.Printf("Successfully initialized OpenBao provider using %s method", o.config.AuthMethod)
	return nil
}

// GetSecret retrieves a secret value from OpenBao
func (o *OpenBaoProvider) GetSecret(ctx context.Context, req secrets.Request) ([]byte, error) {
	secretPath := o.buildSecretPath(req)
	log.Printf("Reading secret from OpenBao path: %s", secretPath)

	// Read secret from OpenBao
	secret, err := o.client.Logical().ReadWithContext(ctx, secretPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret from OpenBao: %v", err)
	}

	if secret == nil {
		return nil, fmt.Errorf("secret not found at path: %s", secretPath)
	}

	// Extract the secret value
	value, err := o.extractSecretValue(secret, req)
	if err != nil {
		return nil, fmt.Errorf("failed to extract secret value: %v", err)
	}

	log.Printf("Successfully retrieved secret from OpenBao")
	return value, nil
}

// SupportsRotation indicates that OpenBao supports secret rotation monitoring
func (o *OpenBaoProvider) SupportsRotation() bool {
	return true
}

// CheckSecretChanged checks if a secret has changed in OpenBao
func (o *OpenBaoProvider) CheckSecretChanged(ctx context.Context, secretInfo *SecretInfo) (bool, error) {
	// Read secret from OpenBao
	secret, err := o.client.Logical().ReadWithContext(ctx, secretInfo.SecretPath)
	if err != nil {
		return false, fmt.Errorf("error reading secret from OpenBao: %v", err)
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
func (o *OpenBaoProvider) GetProviderName() string {
	return "openbao"
}

// Close performs cleanup for the OpenBao provider
func (o *OpenBaoProvider) Close() error {
	// OpenBao client doesn't require explicit cleanup
	return nil
}

// authenticate handles various OpenBao authentication methods
func (o *OpenBaoProvider) authenticate() error {
	switch o.config.AuthMethod {
	case "token":
		if o.config.Token == "" {
			return fmt.Errorf("OPENBAO_TOKEN is required for token authentication")
		}
		o.client.SetToken(o.config.Token)

	case "approle":
		if o.config.RoleID == "" || o.config.SecretID == "" {
			return fmt.Errorf("OPENBAO_ROLE_ID and OPENBAO_SECRET_ID are required for approle authentication")
		}

		data := map[string]interface{}{
			"role_id":   o.config.RoleID,
			"secret_id": o.config.SecretID,
		}

		resp, err := o.client.Logical().Write("auth/approle/login", data)
		if err != nil {
			return fmt.Errorf("approle authentication failed: %v", err)
		}

		if resp.Auth == nil {
			return fmt.Errorf("no auth info returned from approle login")
		}

		o.client.SetToken(resp.Auth.ClientToken)

	case "jwt", "oidc":
		// JWT/OIDC authentication
		// https://openbao.org/docs/auth/jwt
		if o.config.JWTToken == "" {
			return fmt.Errorf("OPENBAO_JWT_TOKEN is required for %s authentication", o.config.AuthMethod)
		}
		if o.config.OIDCRole == "" {
			return fmt.Errorf("OPENBAO_OIDC_ROLE is required for %s authentication", o.config.AuthMethod)
		}

		data := map[string]interface{}{
			"jwt":  o.config.JWTToken,
			"role": o.config.OIDCRole,
		}

		loginPath := fmt.Sprintf("auth/%s/login", o.config.AuthMethod)
		resp, err := o.client.Logical().Write(loginPath, data)
		if err != nil {
			return fmt.Errorf("%s authentication failed: %v", o.config.AuthMethod, err)
		}

		if resp == nil || resp.Auth == nil {
			return fmt.Errorf("no auth info returned from %s login", o.config.AuthMethod)
		}

		o.client.SetToken(resp.Auth.ClientToken)
		log.Printf("Successfully authenticated with OpenBao using %s method (role: %s)",
			o.config.AuthMethod, o.config.OIDCRole)

	default:
		return fmt.Errorf("unsupported authentication method: %s", o.config.AuthMethod)
	}

	return nil
}

// buildSecretPath constructs the OpenBao secret path based on request labels and service information
func (o *OpenBaoProvider) buildSecretPath(req secrets.Request) string {
	// Use custom path from labels if provided
	if customPath, exists := req.SecretLabels["openbao_path"]; exists {
		// For KV v2, ensure we have the /data/ prefix
		if o.config.MountPath == "secret" {
			return fmt.Sprintf("%s/data/%s", o.config.MountPath, customPath)
		}
		return fmt.Sprintf("%s/%s", o.config.MountPath, customPath)
	}

	// Default path structure for KV v2
	if o.config.MountPath == "secret" {
		if req.ServiceName != "" {
			return fmt.Sprintf("%s/data/%s/%s", o.config.MountPath, req.ServiceName, req.SecretName)
		}
		return fmt.Sprintf("%s/data/%s", o.config.MountPath, req.SecretName)
	}

	// For other mount paths
	if req.ServiceName != "" {
		return fmt.Sprintf("%s/%s/%s", o.config.MountPath, req.ServiceName, req.SecretName)
	}
	return fmt.Sprintf("%s/%s", o.config.MountPath, req.SecretName)
}

// extractSecretValue extracts the appropriate value from the OpenBao response
func (o *OpenBaoProvider) extractSecretValue(secret *api.Secret, req secrets.Request) ([]byte, error) {
	// For KV v2, data is nested under "data"
	var data map[string]interface{}
	if secretData, ok := secret.Data["data"]; ok {
		data = secretData.(map[string]interface{})
	} else {
		data = secret.Data
	}

	// Check for specific field in labels
	if field, exists := req.SecretLabels["openbao_field"]; exists {
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

// GetSecretVersion retrieves a specific version of a secret from OpenBao KV v2.
func (o *OpenBaoProvider) GetSecretVersion(ctx context.Context, req secrets.Request, version string) ([]byte, error) {
	secretPath := o.buildSecretPath(req)

	var versionedPath string
	if version == "" || version == "latest" {
		versionedPath = secretPath
	} else {
		versionedPath = fmt.Sprintf("%s?version=%s", secretPath, version)
	}

	log.Printf("Reading secret version '%s' from OpenBao path: %s", version, versionedPath)

	secret, err := o.client.Logical().ReadWithContext(ctx, versionedPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret version %s from OpenBao: %v", version, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("secret version %s not found at path: %s", version, secretPath)
	}

	return o.extractSecretValue(secret, req)
}
