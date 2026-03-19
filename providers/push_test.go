package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockVaultServer creates a minimal Vault KV v2 mock server for testing PushSecret
func mockVaultServer(t *testing.T) (*httptest.Server, *map[string]interface{}) {
	t.Helper()
	store := make(map[string]interface{})

	mux := http.NewServeMux()

	// KV v2 write endpoint
	mux.HandleFunc("/v1/secret/data/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v1/")
		switch r.Method {
		case http.MethodPut, http.MethodPost:
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			store[path] = body
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"version": 1},
			})
		case http.MethodGet:
			if val, ok := store[path]; ok {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": val})
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		}
	})

	// KV v2 metadata delete endpoint
	mux.HandleFunc("/v1/secret/metadata/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			path := strings.TrimPrefix(r.URL.Path, "/v1/")
			path = strings.Replace(path, "metadata", "data", 1)
			delete(store, path)
			w.WriteHeader(http.StatusNoContent)
		}
	})

	// Token auth endpoint
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"id": "test-token"},
		})
	})

	return httptest.NewServer(mux), &store
}

func newTestVaultProvider(t *testing.T, serverURL string) *VaultProvider {
	t.Helper()
	p := &VaultProvider{}
	err := p.Initialize(map[string]string{
		"VAULT_ADDR":        serverURL,
		"VAULT_AUTH_METHOD": "token",
		"VAULT_TOKEN":       "test-token",
		"VAULT_MOUNT_PATH":  "secret",
	})
	if err != nil {
		t.Fatalf("failed to initialize VaultProvider: %v", err)
	}
	return p
}

func TestVaultProvider_SupportsPush(t *testing.T) {
	p := &VaultProvider{}
	if !p.SupportsPush() {
		t.Error("expected SupportsPush true for Vault")
	}
}

func TestVaultProvider_PushSecret(t *testing.T) {
	srv, _ := mockVaultServer(t)
	defer srv.Close()

	p := newTestVaultProvider(t, srv.URL)

	resp, err := p.PushSecret(context.Background(), PushSecretRequest{
		SecretName:  "db-password",
		SecretValue: []byte("mysecretvalue"),
		RemotePath:  "database/mysql",
		RemoteField: "password",
	})
	if err != nil {
		t.Fatalf("PushSecret failed: %v", err)
	}
	if resp.RemotePath == "" {
		t.Error("expected non-empty RemotePath in response")
	}
}

func TestVaultProvider_PushSecret_DefaultField(t *testing.T) {
	srv, _ := mockVaultServer(t)
	defer srv.Close()

	p := newTestVaultProvider(t, srv.URL)

	// No RemoteField specified — should default to "value"
	_, err := p.PushSecret(context.Background(), PushSecretRequest{
		SecretName:  "api-key",
		SecretValue: []byte("myapikey"),
		RemotePath:  "app/api",
		RemoteField: "",
	})
	if err != nil {
		t.Fatalf("PushSecret with default field failed: %v", err)
	}
}

func TestVaultProvider_DeleteSecret(t *testing.T) {
	srv, _ := mockVaultServer(t)
	defer srv.Close()

	p := newTestVaultProvider(t, srv.URL)

	err := p.DeleteSecret(context.Background(), DeleteSecretRequest{
		RemotePath: "database/mysql",
	})
	if err != nil {
		t.Fatalf("DeleteSecret failed: %v", err)
	}
}

func TestPushSecretReconciler_New(t *testing.T) {
	srv, _ := mockVaultServer(t)
	defer srv.Close()

	p := newTestVaultProvider(t, srv.URL)
	reconciler, err := NewPushSecretReconciler(p)
	if err != nil {
		t.Fatalf("NewPushSecretReconciler failed: %v", err)
	}
	if reconciler == nil {
		t.Fatal("expected non-nil reconciler")
	}
}
