package providers

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/docker/go-plugins-helpers/secrets"
	log "github.com/sirupsen/logrus"
)

// InfisicalProvider implements the SecretsProvider interface for Infisical.
// API reference: https://infisical.com/docs/api-reference/overview/introduction
type InfisicalProvider struct {
	client      *http.Client
	config      *InfisicalConfig
	accessToken string
	tokenExpiry time.Time
	tokenMu     sync.Mutex
}

// InfisicalConfig holds configuration for the Infisical provider.
type InfisicalConfig struct {
	Host         string
	ClientID     string
	ClientSecret string
	ProjectID    string
	Environment  string
	SecretPath   string
	TLS          TLSConfig
}

// infisicalAuthResponse is the response from POST /api/v1/auth/universal-auth/login
type infisicalAuthResponse struct {
	AccessToken string `json:"accessToken"`
	TokenType   string `json:"tokenType"`
	ExpiresIn   int    `json:"expiresIn"`
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

	// Authenticate on startup
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
//   infisical_project     - project ID (falls back to INFISICAL_PROJECT_ID)
//   infisical_environment - environment slug (falls back to INFISICAL_ENVIRONMENT)
//   infisical_path        - folder path (falls back to INFISICAL_SECRET_PATH)
//   infisical_key         - secret key name (defaults to SecretName)
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
	return true
}

// CheckSecretChanged checks if an Infisical secret has changed since last retrieval.
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
// It stores the token expiry time for automatic refresh.
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

	i.tokenMu.Lock()
	i.accessToken = authResp.AccessToken
	// Refresh 60 seconds before actual expiry to avoid race conditions
	if authResp.ExpiresIn > 0 {
		i.tokenExpiry = time.Now().Add(time.Duration(authResp.ExpiresIn-60) * time.Second)
	} else {
		// Default: treat token as valid for 1 hour if server does not return expiry
		i.tokenExpiry = time.Now().Add(1 * time.Hour)
	}
	i.tokenMu.Unlock()

	log.Infof("Successfully authenticated with Infisical (token valid until: %s)",
		i.tokenExpiry.Format(time.RFC3339))
	return nil
}

// isTokenExpired checks whether the current access token has expired.
func (i *InfisicalProvider) isTokenExpired() bool {
	i.tokenMu.Lock()
	defer i.tokenMu.Unlock()
	return time.Now().After(i.tokenExpiry)
}

// refreshIfExpired re-authenticates with Infisical if the token has expired.
func (i *InfisicalProvider) refreshIfExpired(ctx context.Context) error {
	if !i.isTokenExpired() {
		return nil
	}
	log.Infof("Infisical access token expired, refreshing...")
	return i.authenticate(ctx)
}

// doGet performs an authenticated GET request to the Infisical API.
// It automatically refreshes the token if expired, and retries once on 401.
func (i *InfisicalProvider) doGet(ctx context.Context, url string) ([]byte, error) {
	// Proactively refresh if token is near expiry
	if err := i.refreshIfExpired(ctx); err != nil {
		return nil, fmt.Errorf("failed to refresh Infisical token: %w", err)
	}

	body, statusCode, err := i.doGetRequest(ctx, url)
	if err != nil {
		return nil, err
	}

	// On 401, attempt one token refresh and retry
	if statusCode == http.StatusUnauthorized {
		log.Infof("Infisical returned 401, attempting token refresh and retry...")
		if err := i.authenticate(ctx); err != nil {
			return nil, fmt.Errorf("token refresh failed after 401: %w", err)
		}
		body, statusCode, err = i.doGetRequest(ctx, url)
		if err != nil {
			return nil, err
		}
		if statusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("Infisical returned 401 after token refresh — check credentials")
		}
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("Infisical API returned HTTP %d: %s", statusCode, string(body))
	}

	return body, nil
}

// doGetRequest executes a single GET request and returns the body and status code.
func (i *InfisicalProvider) doGetRequest(ctx context.Context, url string) ([]byte, int, error) {
	i.tokenMu.Lock()
	token := i.accessToken
	i.tokenMu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := i.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("HTTP request to Infisical failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read response body: %w", err)
	}

	return body, resp.StatusCode, nil
}
