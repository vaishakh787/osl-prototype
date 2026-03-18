package providers

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// TLSConfig holds TLS/mTLS configuration for a provider
type TLSConfig struct {
	// CABundle is a PEM-encoded CA certificate or bundle used to verify the server
	CABundle string
	// ClientCert is a PEM-encoded client certificate for mTLS
	ClientCert string
	// ClientKey is a PEM-encoded client private key for mTLS
	ClientKey string
	// Insecure skips TLS certificate verification (not recommended for production)
	Insecure bool
}

// BuildTLSConfig constructs a *tls.Config from the given TLSConfig.
// It supports:
//   - Raw PEM-encoded CABundle (single cert or bundle of multiple certs)
//   - mTLS via ClientCert + ClientKey
//   - Insecure mode (skips server cert verification)
func BuildTLSConfig(cfg TLSConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.Insecure, //nolint:gosec // intentional opt-in
	}

	// Load CA bundle if provided
	if cfg.CABundle != "" {
		pool, err := parseCABundle(cfg.CABundle)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CABundle: %w", err)
		}
		tlsCfg.RootCAs = pool
	}

	// Load client certificate + key for mTLS if provided
	if cfg.ClientCert != "" && cfg.ClientKey != "" {
		cert, err := tls.X509KeyPair([]byte(cfg.ClientCert), []byte(cfg.ClientKey))
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate and key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}

// parseCABundle parses a PEM-encoded CA bundle (one or more certificates)
// and returns a *x509.CertPool containing all valid CA certificates found.
func parseCABundle(bundle string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	data := []byte(bundle)
	found := 0

	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate in CABundle: %w", err)
		}
		pool.AddCert(cert)
		found++
	}

	if found == 0 {
		return nil, fmt.Errorf("no valid certificates found in CABundle")
	}

	return pool, nil
}
