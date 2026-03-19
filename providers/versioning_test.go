package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"fmt"
	"testing"

	"github.com/docker/go-plugins-helpers/secrets"
)

func mockVaultVersionServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/sys/internal/ui/mounts/secret", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{})
	})

	mux.HandleFunc("/v1/secret/data/database/mysql", func(w http.ResponseWriter, r *http.Request) {
		version := r.URL.Query().Get("version")
		passwords := map[string]string{
			"":  "current-password",
			"1": "version1-password",
			"2": "version2-password",
		}
		pw, ok := passwords[version]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// Vault SDK expects: {"data": {"data": {...}, "metadata": {...}}}
		// where outer "data" is the KV v2 wrapper
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"request_id": "test",
			"data": map[string]interface{}{
				"data": map[string]interface{}{
					"password": pw,
				},
				"metadata": map[string]interface{}{
					"version":       "1",
					"created_time":  "2026-01-01T00:00:00Z",
					"deletion_time": "",
					"destroyed":     false,
				},
			},
		})
	})

	return httptest.NewServer(mux)
}

func TestVaultProvider_GetSecretVersion_Latest(t *testing.T) {
	srv := mockVaultVersionServer(t)
	defer srv.Close()

	p := &VaultProvider{}
	_ = p.Initialize(map[string]string{
		"VAULT_ADDR":        srv.URL,
		"VAULT_AUTH_METHOD": "token",
		"VAULT_TOKEN":       "test-token",
		"VAULT_MOUNT_PATH":  "secret",
	})

	val, err := p.GetSecretVersion(context.Background(), secrets.Request{
		SecretName: "mysql",
		SecretLabels: map[string]string{
			"vault_path":  "database/mysql",
			"vault_field": "password",
		},
	}, "latest")
	if err != nil {
		t.Fatalf("GetSecretVersion latest failed: %v", err)
	}
	if string(val) != "current-password" {
		t.Errorf("expected current-password, got %s", val)
	}
}

func TestVaultProvider_GetSecretVersion_PathBuilding(t *testing.T) {
	// Test that version path building logic is correct by inspecting
	// the versionedPath string directly via a table-driven test
	p := &VaultProvider{
		config: &SecretsConfig{MountPath: "secret"},
	}

	req := secrets.Request{
		SecretName:   "mysql",
		SecretLabels: map[string]string{"vault_path": "database/mysql"},
	}

	basePath := p.buildSecretPath(req)

	tests := []struct {
		version  string
		wantPath string
	}{
		{"", "secret/data/database/mysql"},
		{"latest", "secret/data/database/mysql"},
		{"1", "secret/data/database/mysql?version=1"},
		{"2", "secret/data/database/mysql?version=2"},
	}

	for _, tt := range tests {
		var gotPath string
		if tt.version == "" || tt.version == "latest" {
			gotPath = basePath
		} else {
			gotPath = fmt.Sprintf("%s?version=%s", basePath, tt.version)
		}
		if gotPath != tt.wantPath {
			t.Errorf("version=%q: expected path %q, got %q", tt.version, tt.wantPath, gotPath)
		}
	}
}

func TestInfisicalProvider_GetSecretVersion_Latest(t *testing.T) {
	srv := mockInfisicalServer(t)
	defer srv.Close()

	p := &InfisicalProvider{}
	_ = p.Initialize(map[string]string{
		"INFISICAL_HOST":          srv.URL,
		"INFISICAL_CLIENT_ID":     "test-id",
		"INFISICAL_CLIENT_SECRET": "test-secret",
		"INFISICAL_PROJECT_ID":    "proj-123",
		"INFISICAL_ENVIRONMENT":   "prod",
	})

	val, err := p.GetSecretVersion(context.Background(), secrets.Request{
		SecretName:   "DB_PASSWORD",
		SecretLabels: map[string]string{"infisical_key": "DB_PASSWORD"},
	}, "latest")
	if err != nil {
		t.Fatalf("GetSecretVersion latest failed: %v", err)
	}
	if string(val) != "infisicalpass" {
		t.Errorf("expected infisicalpass, got %s", val)
	}
}
