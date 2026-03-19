package providers

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/docker/go-plugins-helpers/secrets"
)

func mockDopplerServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v3/configs/config/secret", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		values := map[string]string{"DB_PASSWORD": "dopplerpass123", "API_KEY": "dopplerkey456"}
		val, ok := values[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"secret": map[string]interface{}{
				"name":  name,
				"value": dopplerSecretValue{Raw: val, Computed: val},
			},
		})
	})
	return httptest.NewServer(mux)
}

func TestDopplerProvider_Initialize(t *testing.T) {
	srv := mockDopplerServer(t)
	defer srv.Close()
	p := &DopplerProvider{}
	if err := p.Initialize(map[string]string{
		"DOPPLER_TOKEN": "dp.st.test", "DOPPLER_PROJECT": "myapp",
		"DOPPLER_CONFIG": "prd", "DOPPLER_API_HOST": srv.URL,
	}); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
}

func TestDopplerProvider_Initialize_MissingToken(t *testing.T) {
	p := &DopplerProvider{}
	if err := p.Initialize(map[string]string{"DOPPLER_PROJECT": "myapp", "DOPPLER_CONFIG": "prd"}); err == nil {
		t.Fatal("expected error for missing token")
	}
}

func TestDopplerProvider_GetSecret(t *testing.T) {
	srv := mockDopplerServer(t)
	defer srv.Close()
	p := &DopplerProvider{}
	_ = p.Initialize(map[string]string{
		"DOPPLER_TOKEN": "dp.st.test", "DOPPLER_PROJECT": "myapp",
		"DOPPLER_CONFIG": "prd", "DOPPLER_API_HOST": srv.URL,
	})
	val, err := p.GetSecret(context.Background(), secrets.Request{
		SecretName: "db_password",
		SecretLabels: map[string]string{
			"doppler_project": "myapp", "doppler_config": "prd", "doppler_name": "DB_PASSWORD",
		},
	})
	if err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	}
	if string(val) != "dopplerpass123" {
		t.Errorf("expected dopplerpass123, got %s", val)
	}
}

func TestDopplerProvider_GetSecret_MissingProject(t *testing.T) {
	srv := mockDopplerServer(t)
	defer srv.Close()
	p := &DopplerProvider{}
	_ = p.Initialize(map[string]string{"DOPPLER_TOKEN": "dp.st.test", "DOPPLER_API_HOST": srv.URL})
	_, err := p.GetSecret(context.Background(), secrets.Request{SecretName: "db_password", SecretLabels: map[string]string{}})
	if err == nil {
		t.Fatal("expected error for missing project")
	}
}

func TestDopplerProvider_GetSecret_MissingConfig(t *testing.T) {
	srv := mockDopplerServer(t)
	defer srv.Close()
	p := &DopplerProvider{}
	_ = p.Initialize(map[string]string{
		"DOPPLER_TOKEN": "dp.st.test", "DOPPLER_PROJECT": "myapp", "DOPPLER_API_HOST": srv.URL,
	})
	_, err := p.GetSecret(context.Background(), secrets.Request{
		SecretName:   "db_password",
		SecretLabels: map[string]string{"doppler_project": "myapp"},
	})
	if err == nil {
		t.Fatal("expected error for missing config")
	}
}

func TestDopplerProvider_GetProviderName(t *testing.T) {
	p := &DopplerProvider{}
	if p.GetProviderName() != "doppler" {
		t.Errorf("expected doppler, got %s", p.GetProviderName())
	}
}

func TestDopplerProvider_SupportsRotation(t *testing.T) {
	p := &DopplerProvider{}
	if p.SupportsRotation() {
		t.Error("expected SupportsRotation false for stub")
	}
}

func TestDopplerProvider_Close(t *testing.T) {
	p := &DopplerProvider{}
	if err := p.Close(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDopplerProvider_CheckSecretChanged(t *testing.T) {
	srv := mockDopplerServer(t)
	defer srv.Close()
	p := &DopplerProvider{}
	_ = p.Initialize(map[string]string{
		"DOPPLER_TOKEN":    "dp.st.test",
		"DOPPLER_PROJECT":  "myapp",
		"DOPPLER_CONFIG":   "prd",
		"DOPPLER_API_HOST": srv.URL,
	})

	// Same value hash — should not have changed
	secretInfo := &SecretInfo{
		SecretPath:  "myapp/prd/DB_PASSWORD",
		SecretField: "DB_PASSWORD",
		LastHash:    fmt.Sprintf("%x", sha256.Sum256([]byte("dopplerpass123"))),
	}
	changed, err := p.CheckSecretChanged(context.Background(), secretInfo)
	if err != nil {
		t.Fatalf("CheckSecretChanged failed: %v", err)
	}
	if changed {
		t.Error("expected secret to be unchanged")
	}

	// Different hash — should detect change
	secretInfo.LastHash = fmt.Sprintf("%x", sha256.Sum256([]byte("old-password")))
	changed, err = p.CheckSecretChanged(context.Background(), secretInfo)
	if err != nil {
		t.Fatalf("CheckSecretChanged failed: %v", err)
	}
	if !changed {
		t.Error("expected secret to be changed")
	}
}

func TestDopplerProvider_CheckSecretChanged_InvalidPath(t *testing.T) {
	p := &DopplerProvider{}
	_ = p.Initialize(map[string]string{
		"DOPPLER_TOKEN":    "dp.st.test",
		"DOPPLER_API_HOST": "http://localhost",
	})
	_, err := p.CheckSecretChanged(context.Background(), &SecretInfo{SecretPath: "invalid-path"})
	if err == nil {
		t.Fatal("expected error for invalid secret path")
	}
}

