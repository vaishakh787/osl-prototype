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

// DopplerProvider implements the SecretsProvider interface for Doppler.
// API reference: https://docs.doppler.com/reference/api
//
// NOTE: This is a prototype stub. The core HTTP client, config,
// and interface methods are wired up. Full field extraction
// and rotation support are marked as TODO.
type DopplerProvider struct {
	client *http.Client
	config *DopplerConfig
}

// DopplerConfig holds configuration for the Doppler provider.
type DopplerConfig struct {
	// Token is the Doppler Service Token for authentication
	// https://docs.doppler.com/docs/service-tokens
	Token string
	// Project is the Doppler project name (required if not set in labels)
	Project string
	// Config is the Doppler config/environment name (e.g. "prd", "dev")
	Config string
	// APIHost allows overriding the Doppler API base URL (default: https://api.doppler.com)
	APIHost string
	// TLS holds optional TLS/mTLS configuration
	TLS TLSConfig
}

// dopplerSecretsResponse represents the Doppler API GET /v3/configs/config/secrets response.
type dopplerSecretsResponse struct {
	Secrets map[string]dopplerSecretValue `json:"secrets"`
}

type dopplerSecretValue struct {
	Raw      string `json:"raw"`
	Computed string `json:"computed"`
}

// Initialize sets up the Doppler provider.
func (d *DopplerProvider) Initialize(config map[string]string) error {
	d.config = &DopplerConfig{
		Token:   getConfigOrDefault(config, "DOPPLER_TOKEN", ""),
		Project: getConfigOrDefault(config, "DOPPLER_PROJECT", ""),
		Config:  getConfigOrDefault(config, "DOPPLER_CONFIG", ""),
		APIHost: getConfigOrDefault(config, "DOPPLER_API_HOST", "https://api.doppler.com"),
		TLS: TLSConfig{
			CABundle:   config["DOPPLER_CA_BUNDLE"],
			ClientCert: config["DOPPLER_CLIENT_CERT"],
			ClientKey:  config["DOPPLER_CLIENT_KEY"],
			Insecure:   getConfigOrDefault(config, "DOPPLER_SKIP_VERIFY", "false") == "true",
		},
	}

	if d.config.Token == "" {
		return fmt.Errorf("DOPPLER_TOKEN is required for Doppler provider")
	}

	d.config.APIHost = strings.TrimRight(d.config.APIHost, "/")

	// Build HTTP client with optional TLS config
	transport := &http.Transport{}
	if d.config.TLS.CABundle != "" || d.config.TLS.ClientCert != "" || d.config.TLS.Insecure {
		tlsCfg, err := BuildTLSConfig(d.config.TLS)
		if err != nil {
			return fmt.Errorf("failed to build TLS config for Doppler provider: %w", err)
		}
		transport.TLSClientConfig = tlsCfg
	}

	d.client = &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	log.Infof("Successfully initialized Doppler provider (project: %s, config: %s)",
		d.config.Project, d.config.Config)
	return nil
}

// GetSecret retrieves a secret from Doppler.
//
// Labels used:
//
//	doppler_project - Doppler project name (falls back to DOPPLER_PROJECT)
//	doppler_config  - Doppler config/env name (falls back to DOPPLER_CONFIG)
//	doppler_name    - secret name in Doppler (defaults to SecretName uppercased)
func (d *DopplerProvider) GetSecret(ctx context.Context, req secrets.Request) ([]byte, error) {
	project := req.SecretLabels["doppler_project"]
	if project == "" {
		project = d.config.Project
	}
	if project == "" {
		return nil, fmt.Errorf("doppler_project label or DOPPLER_PROJECT env var is required")
	}

	cfg := req.SecretLabels["doppler_config"]
	if cfg == "" {
		cfg = d.config.Config
	}
	if cfg == "" {
		return nil, fmt.Errorf("doppler_config label or DOPPLER_CONFIG env var is required")
	}

	// Doppler secret names are conventionally uppercase
	secretName := req.SecretLabels["doppler_name"]
	if secretName == "" {
		secretName = strings.ToUpper(req.SecretName)
	}

	log.Infof("Fetching Doppler secret '%s' from project '%s' config '%s'",
		secretName, project, cfg)

	url := fmt.Sprintf("%s/v3/configs/config/secret?project=%s&config=%s&name=%s",
		d.config.APIHost, project, cfg, secretName)

	body, err := d.doGet(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Doppler secret: %w", err)
	}

	// TODO: parse the single-secret response format
	// Doppler GET /v3/configs/config/secret returns {"secret": {"name": ..., "value": {"raw": ..., "computed": ...}}}
	var result struct {
		Secret struct {
			Value dopplerSecretValue `json:"value"`
		} `json:"secret"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse Doppler response: %w", err)
	}

	if result.Secret.Value.Computed == "" {
		return nil, fmt.Errorf("Doppler secret '%s' has no computed value", secretName)
	}

	log.Infof("Successfully retrieved secret from Doppler")
	return []byte(result.Secret.Value.Computed), nil
}

// SupportsRotation indicates that Doppler supports rotation monitoring.
func (d *DopplerProvider) SupportsRotation() bool {
	// TODO: implement rotation via Doppler webhooks or polling
	return false
}

// CheckSecretChanged checks if a Doppler secret has changed.
func (d *DopplerProvider) CheckSecretChanged(ctx context.Context, secretInfo *SecretInfo) (bool, error) {
	// SecretPath format: "project/config/SECRET_NAME"
	parts := strings.SplitN(secretInfo.SecretPath, "/", 3)
	if len(parts) != 3 {
		return false, fmt.Errorf("invalid Doppler secret path '%s': expected 'project/config/SECRET_NAME'",
			secretInfo.SecretPath)
	}

	url := fmt.Sprintf("%s/v3/configs/config/secret?project=%s&config=%s&name=%s",
		d.config.APIHost, parts[0], parts[1], parts[2])

	body, err := d.doGet(ctx, url)
	if err != nil {
		return false, fmt.Errorf("failed to fetch Doppler secret for rotation check: %w", err)
	}

	var result struct {
		Secret struct {
			Value dopplerSecretValue `json:"value"`
		} `json:"secret"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return false, fmt.Errorf("failed to parse Doppler response: %w", err)
	}

	currentHash := fmt.Sprintf("%x", sha256.Sum256([]byte(result.Secret.Value.Computed)))
	return currentHash != secretInfo.LastHash, nil
}

// GetProviderName returns the name of this provider.
func (d *DopplerProvider) GetProviderName() string {
	return "doppler"
}

// Close performs cleanup for the Doppler provider.
func (d *DopplerProvider) Close() error {
	return nil
}

// doGet performs an authenticated GET request to the Doppler API.
func (d *DopplerProvider) doGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	// Doppler uses HTTP Basic Auth with the token as username and empty password
	req.SetBasicAuth(d.config.Token, "")
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request to Doppler failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Doppler API returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// GetSecretVersion retrieves a specific version of a Doppler secret.
// Doppler does not expose historical secret versions via the API —
// this returns the current version and logs a warning if a specific version is requested.
func (d *DopplerProvider) GetSecretVersion(ctx context.Context, req secrets.Request, version string) ([]byte, error) {
	if version != "" && version != "latest" {
		log.Warnf("Doppler does not support secret version pinning — returning current version")
	}
	return d.GetSecret(ctx, req)
}
