package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/docker/go-plugins-helpers/secrets"
)

func mockOPServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/vaults", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]onePasswordVault{{ID: "aaaabbbbccccddddeeeeffffgg", Name: "test-vault"}})
	})
	mux.HandleFunc("/v1/vaults/aaaabbbbccccddddeeeeffffgg/items", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]struct {
			ID    string `json:"id"`
			Title string `json:"title"`
		}{{ID: "zzzzyyyyxxxxwwwwvvvvuuuutt", Title: "my-database"}})
	})
	mux.HandleFunc("/v1/vaults/aaaabbbbccccddddeeeeffffgg/items/zzzzyyyyxxxxwwwwvvvvuuuutt", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(onePasswordItem{
			ID:    "zzzzyyyyxxxxwwwwvvvvuuuutt",
			Title: "my-database",
			Fields: []onePasswordField{
				{ID: "username", Label: "username", Value: "admin", Type: "STRING"},
				{ID: "password", Label: "password", Value: "supersecret123", Type: "CONCEALED"},
			},
		})
	})
	return httptest.NewServer(mux)
}

func TestOnePasswordProvider_Initialize(t *testing.T) {
	srv := mockOPServer(t)
	defer srv.Close()
	p := &OnePasswordProvider{}
	if err := p.Initialize(map[string]string{"OP_CONNECT_HOST": srv.URL, "OP_CONNECT_TOKEN": "tok", "OP_VAULT": "test-vault"}); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
}

func TestOnePasswordProvider_Initialize_MissingHost(t *testing.T) {
	p := &OnePasswordProvider{}
	if err := p.Initialize(map[string]string{"OP_CONNECT_TOKEN": "tok"}); err == nil {
		t.Fatal("expected error for missing host")
	}
}

func TestOnePasswordProvider_Initialize_MissingToken(t *testing.T) {
	p := &OnePasswordProvider{}
	if err := p.Initialize(map[string]string{"OP_CONNECT_HOST": "http://localhost"}); err == nil {
		t.Fatal("expected error for missing token")
	}
}

func TestOnePasswordProvider_GetSecret_Password(t *testing.T) {
	srv := mockOPServer(t)
	defer srv.Close()
	p := &OnePasswordProvider{}
	_ = p.Initialize(map[string]string{"OP_CONNECT_HOST": srv.URL, "OP_CONNECT_TOKEN": "tok", "OP_VAULT": "test-vault"})
	val, err := p.GetSecret(context.Background(), secrets.Request{
		SecretName:   "my-database",
		SecretLabels: map[string]string{"op_vault": "test-vault", "op_item": "my-database", "op_field": "password"},
	})
	if err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	}
	if string(val) != "supersecret123" {
		t.Errorf("expected 'supersecret123', got '%s'", val)
	}
}

func TestOnePasswordProvider_GetSecret_Username(t *testing.T) {
	srv := mockOPServer(t)
	defer srv.Close()
	p := &OnePasswordProvider{}
	_ = p.Initialize(map[string]string{"OP_CONNECT_HOST": srv.URL, "OP_CONNECT_TOKEN": "tok"})
	val, err := p.GetSecret(context.Background(), secrets.Request{
		SecretName:   "my-database",
		SecretLabels: map[string]string{"op_vault": "test-vault", "op_item": "my-database", "op_field": "username"},
	})
	if err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	}
	if string(val) != "admin" {
		t.Errorf("expected 'admin', got '%s'", val)
	}
}

func TestOnePasswordProvider_GetSecret_FieldNotFound(t *testing.T) {
	srv := mockOPServer(t)
	defer srv.Close()
	p := &OnePasswordProvider{}
	_ = p.Initialize(map[string]string{"OP_CONNECT_HOST": srv.URL, "OP_CONNECT_TOKEN": "tok"})
	_, err := p.GetSecret(context.Background(), secrets.Request{
		SecretName:   "my-database",
		SecretLabels: map[string]string{"op_vault": "test-vault", "op_item": "my-database", "op_field": "nonexistent"},
	})
	if err == nil {
		t.Fatal("expected error for missing field")
	}
}

func TestOnePasswordProvider_GetSecret_MissingVault(t *testing.T) {
	srv := mockOPServer(t)
	defer srv.Close()
	p := &OnePasswordProvider{}
	_ = p.Initialize(map[string]string{"OP_CONNECT_HOST": srv.URL, "OP_CONNECT_TOKEN": "tok"})
	_, err := p.GetSecret(context.Background(), secrets.Request{SecretName: "my-database", SecretLabels: map[string]string{}})
	if err == nil {
		t.Fatal("expected error when vault not set")
	}
}

func TestOnePasswordProvider_GetProviderName(t *testing.T) {
	p := &OnePasswordProvider{}
	if p.GetProviderName() != "1password" {
		t.Errorf("expected '1password', got '%s'", p.GetProviderName())
	}
}

func TestOnePasswordProvider_SupportsRotation(t *testing.T) {
	p := &OnePasswordProvider{}
	if !p.SupportsRotation() {
		t.Error("expected SupportsRotation true")
	}
}

func TestOnePasswordProvider_Close(t *testing.T) {
	p := &OnePasswordProvider{}
	if err := p.Close(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestIsLikelyUUID(t *testing.T) {
	tests := []struct{ input string; want bool }{
		{"aaaabbbbccccddddeeeeffffgg", true},
		{"test-vault", false},
		{"short", false},
		{"aaaabbbbccccddddeeeeffffgg1", false},
	}
	for _, tt := range tests {
		if got := isLikelyUUID(tt.input); got != tt.want {
			t.Errorf("isLikelyUUID(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
