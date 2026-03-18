package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/docker/go-plugins-helpers/secrets"
)

func mockInfisicalServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/universal-auth/login", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(infisicalAuthResponse{AccessToken: "test-access-token", TokenType: "Bearer"})
	})
	mux.HandleFunc("/api/v3/secrets/raw/", func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Path[len("/api/v3/secrets/raw/"):]
		values := map[string]string{"DB_HOST": "localhost", "DB_PASSWORD": "infisicalpass"}
		val, ok := values[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"secret": infisicalSecret{SecretKey: key, SecretValue: val},
		})
	})
	return httptest.NewServer(mux)
}

func TestInfisicalProvider_Initialize(t *testing.T) {
	srv := mockInfisicalServer(t)
	defer srv.Close()
	p := &InfisicalProvider{}
	if err := p.Initialize(map[string]string{
		"INFISICAL_HOST": srv.URL, "INFISICAL_CLIENT_ID": "test-id",
		"INFISICAL_CLIENT_SECRET": "test-secret", "INFISICAL_PROJECT_ID": "proj-123",
		"INFISICAL_ENVIRONMENT": "prod",
	}); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
}

func TestInfisicalProvider_Initialize_MissingClientID(t *testing.T) {
	srv := mockInfisicalServer(t)
	defer srv.Close()
	p := &InfisicalProvider{}
	if err := p.Initialize(map[string]string{
		"INFISICAL_HOST": srv.URL, "INFISICAL_CLIENT_SECRET": "test-secret", "INFISICAL_PROJECT_ID": "proj-123",
	}); err == nil {
		t.Fatal("expected error for missing client ID")
	}
}

func TestInfisicalProvider_Initialize_MissingProjectID(t *testing.T) {
	srv := mockInfisicalServer(t)
	defer srv.Close()
	p := &InfisicalProvider{}
	if err := p.Initialize(map[string]string{
		"INFISICAL_HOST": srv.URL, "INFISICAL_CLIENT_ID": "test-id", "INFISICAL_CLIENT_SECRET": "test-secret",
	}); err == nil {
		t.Fatal("expected error for missing project ID")
	}
}

func TestInfisicalProvider_GetSecret(t *testing.T) {
	srv := mockInfisicalServer(t)
	defer srv.Close()
	p := &InfisicalProvider{}
	_ = p.Initialize(map[string]string{
		"INFISICAL_HOST": srv.URL, "INFISICAL_CLIENT_ID": "test-id",
		"INFISICAL_CLIENT_SECRET": "test-secret", "INFISICAL_PROJECT_ID": "proj-123",
		"INFISICAL_ENVIRONMENT": "prod",
	})
	val, err := p.GetSecret(context.Background(), secrets.Request{
		SecretName:   "DB_PASSWORD",
		SecretLabels: map[string]string{"infisical_key": "DB_PASSWORD"},
	})
	if err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	}
	if string(val) != "infisicalpass" {
		t.Errorf("expected infisicalpass, got %s", val)
	}
}

func TestInfisicalProvider_GetProviderName(t *testing.T) {
	p := &InfisicalProvider{}
	if p.GetProviderName() != "infisical" {
		t.Errorf("expected infisical, got %s", p.GetProviderName())
	}
}

func TestInfisicalProvider_SupportsRotation(t *testing.T) {
	p := &InfisicalProvider{}
	if p.SupportsRotation() {
		t.Error("expected SupportsRotation false for stub")
	}
}

func TestInfisicalProvider_Close(t *testing.T) {
	p := &InfisicalProvider{}
	if err := p.Close(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
