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

type OnePasswordProvider struct {
	client *http.Client
	config *OnePasswordConfig
}

type OnePasswordConfig struct {
	ConnectHost  string
	Token        string
	DefaultVault string
	TLS          TLSConfig
}

type onePasswordItem struct {
	ID     string             `json:"id"`
	Title  string             `json:"title"`
	Fields []onePasswordField `json:"fields"`
}

type onePasswordField struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Value string `json:"value"`
	Type  string `json:"type"`
}

type onePasswordVault struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (op *OnePasswordProvider) Initialize(config map[string]string) error {
	op.config = &OnePasswordConfig{
		ConnectHost:  getConfigOrDefault(config, "OP_CONNECT_HOST", ""),
		Token:        getConfigOrDefault(config, "OP_CONNECT_TOKEN", ""),
		DefaultVault: getConfigOrDefault(config, "OP_VAULT", ""),
		TLS: TLSConfig{
			CABundle:   config["OP_CA_BUNDLE"],
			ClientCert: config["OP_CLIENT_CERT"],
			ClientKey:  config["OP_CLIENT_KEY"],
			Insecure:   getConfigOrDefault(config, "OP_SKIP_VERIFY", "false") == "true",
		},
	}
	if op.config.ConnectHost == "" {
		return fmt.Errorf("OP_CONNECT_HOST is required for 1Password provider")
	}
	if op.config.Token == "" {
		return fmt.Errorf("OP_CONNECT_TOKEN is required for 1Password provider")
	}
	op.config.ConnectHost = strings.TrimRight(op.config.ConnectHost, "/")
	transport := &http.Transport{}
	if op.config.TLS.CABundle != "" || op.config.TLS.ClientCert != "" || op.config.TLS.Insecure {
		tlsCfg, err := BuildTLSConfig(op.config.TLS)
		if err != nil {
			return fmt.Errorf("failed to build TLS config for 1Password provider: %w", err)
		}
		transport.TLSClientConfig = tlsCfg
	}
	op.client = &http.Client{Transport: transport, Timeout: 30 * time.Second}
	log.Infof("Successfully initialized 1Password Connect provider at: %s", op.config.ConnectHost)
	return nil
}

func (op *OnePasswordProvider) GetSecret(ctx context.Context, req secrets.Request) ([]byte, error) {
	vaultRef := req.SecretLabels["op_vault"]
	if vaultRef == "" {
		vaultRef = op.config.DefaultVault
	}
	if vaultRef == "" {
		return nil, fmt.Errorf("op_vault label or OP_VAULT env var is required for 1Password provider")
	}
	itemRef := req.SecretLabels["op_item"]
	if itemRef == "" {
		itemRef = req.SecretName
	}
	fieldLabel := req.SecretLabels["op_field"]
	if fieldLabel == "" {
		fieldLabel = "password"
	}
	log.Infof("Fetching 1Password item '%s' from vault '%s', field '%s'", itemRef, vaultRef, fieldLabel)
	vaultUUID, err := op.resolveVaultUUID(ctx, vaultRef)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve 1Password vault '%s': %w", vaultRef, err)
	}
	itemUUID, err := op.resolveItemUUID(ctx, vaultUUID, itemRef)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve 1Password item '%s': %w", itemRef, err)
	}
	item, err := op.getItem(ctx, vaultUUID, itemUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to get 1Password item '%s': %w", itemUUID, err)
	}
	value, err := op.extractField(item, fieldLabel)
	if err != nil {
		return nil, err
	}
	log.Infof("Successfully retrieved secret from 1Password Connect")
	return []byte(value), nil
}

func (op *OnePasswordProvider) SupportsRotation() bool { return true }

func (op *OnePasswordProvider) CheckSecretChanged(ctx context.Context, secretInfo *SecretInfo) (bool, error) {
	parts := strings.SplitN(secretInfo.SecretPath, "/", 2)
	if len(parts) != 2 {
		return false, fmt.Errorf("invalid 1Password secret path '%s': expected 'vaultUUID/itemUUID'", secretInfo.SecretPath)
	}
	item, err := op.getItem(ctx, parts[0], parts[1])
	if err != nil {
		return false, fmt.Errorf("failed to get 1Password item for rotation check: %w", err)
	}
	value, err := op.extractField(item, secretInfo.SecretField)
	if err != nil {
		return false, err
	}
	currentHash := fmt.Sprintf("%x", sha256.Sum256([]byte(value)))
	return currentHash != secretInfo.LastHash, nil
}

func (op *OnePasswordProvider) GetProviderName() string { return "1password" }
func (op *OnePasswordProvider) Close() error            { return nil }

func (op *OnePasswordProvider) resolveVaultUUID(ctx context.Context, vaultRef string) (string, error) {
	if isLikelyUUID(vaultRef) {
		return vaultRef, nil
	}
	body, err := op.doGet(ctx, fmt.Sprintf("%s/v1/vaults", op.config.ConnectHost))
	if err != nil {
		return "", err
	}
	var vaults []onePasswordVault
	if err := json.Unmarshal(body, &vaults); err != nil {
		return "", fmt.Errorf("failed to parse vaults response: %w", err)
	}
	for _, v := range vaults {
		if strings.EqualFold(v.Name, vaultRef) || v.ID == vaultRef {
			return v.ID, nil
		}
	}
	return "", fmt.Errorf("vault '%s' not found in 1Password Connect", vaultRef)
}

func (op *OnePasswordProvider) resolveItemUUID(ctx context.Context, vaultUUID, itemRef string) (string, error) {
	if isLikelyUUID(itemRef) {
		return itemRef, nil
	}
	body, err := op.doGet(ctx, fmt.Sprintf("%s/v1/vaults/%s/items", op.config.ConnectHost, vaultUUID))
	if err != nil {
		return "", err
	}
	var items []struct {
		ID    string `json:"id"`
		Title string `json:"title"`
	}
	if err := json.Unmarshal(body, &items); err != nil {
		return "", fmt.Errorf("failed to parse items list response: %w", err)
	}
	for _, item := range items {
		if strings.EqualFold(item.Title, itemRef) || item.ID == itemRef {
			return item.ID, nil
		}
	}
	return "", fmt.Errorf("item '%s' not found in vault '%s'", itemRef, vaultUUID)
}

func (op *OnePasswordProvider) getItem(ctx context.Context, vaultUUID, itemUUID string) (*onePasswordItem, error) {
	body, err := op.doGet(ctx, fmt.Sprintf("%s/v1/vaults/%s/items/%s", op.config.ConnectHost, vaultUUID, itemUUID))
	if err != nil {
		return nil, err
	}
	var item onePasswordItem
	if err := json.Unmarshal(body, &item); err != nil {
		return nil, fmt.Errorf("failed to parse item response: %w", err)
	}
	return &item, nil
}

func (op *OnePasswordProvider) extractField(item *onePasswordItem, fieldLabel string) (string, error) {
	for _, f := range item.Fields {
		if strings.EqualFold(f.Label, fieldLabel) || strings.EqualFold(f.ID, fieldLabel) {
			return f.Value, nil
		}
	}
	labels := make([]string, 0, len(item.Fields))
	for _, f := range item.Fields {
		labels = append(labels, f.Label)
	}
	return "", fmt.Errorf("field '%s' not found in 1Password item '%s'; available fields: %v", fieldLabel, item.Title, labels)
}

func (op *OnePasswordProvider) doGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+op.config.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := op.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request to 1Password Connect failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("1Password Connect returned HTTP %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

func isLikelyUUID(s string) bool {
	if len(s) != 26 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}
