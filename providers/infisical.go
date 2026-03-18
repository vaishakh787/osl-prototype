package providers

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/docker/go-plugins-helpers/secrets"
	log "github.com/sirupsen/logrus"
)

// InfisicalProvider implements the SecretsProvider interface for Infisical.
// API reference: https://infisical.com/docs/api-reference/overview/introduction
//
// NOTE: This is a prototype stub. The core HTTP client, config,
// and interface methods are wired up. JWT auth token refresh
// and full rotation support are marked as TODO.
type InfisicalProvider struct {
	client      *http.Client
	config      *InfisicalConfig
	accessToken string
}

// InfisicalConfig holds configuration for the Infisical provider.
type InfisicalConfig struct {
	// Host is the Infisical server URL (default: https://app.infisical.com)
	Host string
	// ClientID is the Infisical Machine Identity client ID
	ClientID string
	// ClientSecret is the Infisical Machine Identity client secret
	ClientSecret string
	// ProjectID is the Infisical project ID (workspace ID)
	ProjectID string
	// Environment is the Infisical environment slug (e.g. "prod", "dev")
	Environment string
	// SecretPath is the folder path within the environment (default: "/")
	SecretPath string
	// TLS holds optional TLS/mTLS configuration
	TLS TLSConfig
}

// infisicalAuthResponse is the response from POST /api/v1/auth/universal-auth/login
type infisicalAuthResponse struct {
	AccessToken string `json:"accessToken"`
	TokenType   string `json:"tokenType"`
}

// infisicalSecretsResponse is the response from GET /api/v3/secrets/raw
type infisicalSecretsResponse struct {
	Secrets []infisicalSecret `json:"secrets"`
}

type infisicalSecret struct {
	SecretKey   string `json:"secretKey"`
	SecretValue string `json:"secretValue"`
}

// Initialize sets up the Infisical provider.
func (i *InfisicalProvider) Initialize(config map[string]string) error {
	i.config = &InfisicalConfig{
		Host:         getConfigOrDefault(config, "INFISICAL_HOST", "https://app.infisical.com"),
		ClientID:     getConfigOrDefault(config, "INFISICAL_CLIENT_ID", ""),
		ClientSecret: getConfigOrDefault(config, "INFISICAL_CLIENT_SECRET", ""),
		ProjectID:    getConfigOrDefault(config, "INFISICAL_PROJECT_ID", ""),
		Environment:  getConfigOrDefault(config, "INFISICAL_ENVIRONMENT", "prod"),
		SecretPath:   getConfigOrDefault(config, "INFISICAL_SECRET_PATH", "/"),
		TLS: TLSConfig{
			CABundle:   config["INFISICAL_CA_BUNDLE"],
			ClientCert: config["INFISICAL_CLIENT_CERT"],
			ClientKey:  config["INFISICAL_CLIENT_KEY"],
			Insecure:   getConfigOrDefault(config, "INFISICAL_SKIP_VERIFY", "false") == "true",
		},
	}

	if i.config.ClientID == "" || i.config.ClientSecret == "" {
		return fmt.Errorf("INFISICAL_CLIENT_ID and INFISICAL_CLIENT_SECRET are required for Infisical provider")
	}
	if i.config.ProjectID == "" {
		return fmt.Errorf("INFISICAL_PROJECT_ID is required for Infisical provider")
	}

	i.config.Host = strings.TrimRight(i.config.Host, "/")

	// Build HTTP client with optional TLS config
	transport := &http.Transport{}
	if i.config.TLS.CABundle != "" || i.config.TLS.ClientCert != "" || i.config.TLS.Insecure {
		tlsCfg, err := BuildTLSConfig(i.config.TLS)
		if err != nil {
			return fmt.Errorf("failed to build TLS config for Infisical provider: %w", err)
		}
		transport.TLSClientConfig = tlsCfg
	}

	i.client = &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	// Authenticate with Infisical using Universal Auth (Machine Identity)
	// https://infisical.com/docs/documentation/platform/identities/universal-auth
	if err := i.authenticate(context.Background()); err != nil {
		return fmt.Errorf("failed to authenticate with Infisical: %w", err)
	}

	log.Infof("Successfully initialized Infisical provider (project: %s, env: %s)",
		i.config.ProjectID, i.config.Environment)
	return nil
}

// GetSecret retrieves a secret from Infisical.
//
// Labels used:
//
//	infisical_project     - project ID (falls back to INFISICAL_PROJECT_ID)
//	infisical_environment - environment slug (falls back to INFISICAL_ENVIRONMENT)
//	infisical_path        - folder path (falls back to INFISICAL_SECRET_PATH)
//	infisical_key         - secret key name (defaults to SecretName uppercased)
func (i *InfisicalProvider) GetSecret(ctx context.Context, req secrets.Request) ([]byte, error) {
	projectID := req.SecretLabels["infisical_project"]
	if projectID == "" {
		projectID = i.config.ProjectID
	}

	environment := req.SecretLabels["infisical_environment"]
	if environment == "" {
		environment = i.config.Environment
	}

	secretPath := req.SecretLabels["infisical_path"]
	if secretPath == "" {
		secretPath = i.config.SecretPath
	}

	secretKey := req.SecretLabels["infisical_key"]
	if secretKey == "" {
		secretKey = req.SecretName
	}

	log.Infof("Fetching Infisical secret '%s' (project: %s, env: %s, path: %s)",
		secretKey, projectID, environment, secretPath)

	url := fmt.Sprintf("%s/api/v3/secrets/raw/%s?workspaceId=%s&environment=%s&secretPath=%s",
		i.config.Host, secretKey, projectID, environment, secretPath)

	body, err := i.doGet(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Infisical secret: %w", err)
	}

	var result struct {
		Secret infisicalSecret `json:"secret"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse Infisical response: %w", err)
	}

	if result.Secret.SecretValue == "" {
		return nil, fmt.Errorf("Infisical secret '%s' has no value", secretKey)
	}

	log.Infof("Successfully retrieved secret from Infisical")
	return []byte(result.Secret.SecretValue), nil
}

// SupportsRotation indicates that Infisical supports rotation monitoring.
func (i *InfisicalProvider) SupportsRotation() bool {
	// TODO: implement rotation polling
	return false
}

// CheckSecretChanged checks if an Infisical secret has changed.
func (i *InfisicalProvider) CheckSecretChanged(ctx context.Context, secretInfo *SecretInfo) (bool, error) {
	// SecretPath format: "projectID/environment/path/KEY"
	parts := strings.SplitN(secretInfo.SecretPath, "/", 4)
	if len(parts) < 3 {
		return false, fmt.Errorf("invalid Infisical secret path '%s': expected 'projectID/environment/path/KEY'",
			secretInfo.SecretPath)
	}

	projectID := parts[0]
	environment := parts[1]
	secretPath := "/" + parts[2]
	secretKey := secretInfo.SecretField

	url := fmt.Sprintf("%s/api/v3/secrets/raw/%s?workspaceId=%s&environment=%s&secretPath=%s",
		i.config.Host, secretKey, projectID, environment, secretPath)

	body, err := i.doGet(ctx, url)
	if err != nil {
		return false, fmt.Errorf("failed to fetch Infisical secret for rotation check: %w", err)
	}

	var result struct {
		Secret infisicalSecret `json:"secret"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return false, fmt.Errorf("failed to parse Infisical response: %w", err)
	}

	currentHash := fmt.Sprintf("%x", sha256.Sum256([]byte(result.Secret.SecretValue)))
	return currentHash != secretInfo.LastHash, nil
}

// GetProviderName returns the name of this provider.
func (i *InfisicalProvider) GetProviderName() string {
	return "infisical"
}

// Close performs cleanup for the Infisical provider.
func (i *InfisicalProvider) Close() error {
	return nil
}

// authenticate obtains a short-lived access token from Infisical using Universal Auth.
// TODO: implement token refresh when token expires
func (i *InfisicalProvider) authenticate(ctx context.Context) error {
	url := fmt.Sprintf("%s/api/v1/auth/universal-auth/login", i.config.Host)

	payload := fmt.Sprintf(`{"clientId":"%s","clientSecret":"%s"}`,
		i.config.ClientID, i.config.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url,
		strings.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := i.client.Do(req)
	if err != nil {
		return fmt.Errorf("auth request to Infisical failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Infisical auth returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var authResp infisicalAuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return fmt.Errorf("failed to parse Infisical auth response: %w", err)
	}

	if authResp.AccessToken == "" {
		return fmt.Errorf("Infisical auth response contained no access token")
	}

	i.accessToken = authResp.AccessToken
	log.Infof("Successfully authenticated with Infisical")
	return nil
}

// doGet performs an authenticated GET request to the Infisical API.
func (i *InfisicalProvider) doGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+i.accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := i.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request to Infisical failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		// TODO: attempt token refresh here
		return nil, fmt.Errorf("Infisical returned 401 Unauthorized — token may have expired")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Infisical API returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}
