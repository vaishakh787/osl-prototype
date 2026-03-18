# swarm-external-secrets — GSoC 2026 Prototype

This branch (`osl-prototype`) is a prototype implementation for the
**Google Summer of Code 2026** project idea:
**"Implement Enterprise Security & Provider Ecosystem Expansion"**
under [OpenScienceLabs](http://opensciencelabs.org/).

---

## What This Prototype Demonstrates

This prototype extends `swarm-external-secrets` with three major workstreams
from the GSoC proposal:

### 1. New Provider Integrations

Three new secret backends have been added alongside the existing five
(Vault, AWS, GCP, Azure, OpenBao):

| Provider | Status | Auth Method | Rotation |
|---|---|---|---|
| 1Password Connect | ✅ Full implementation | Connect API Token | ✅ |
| Doppler | 🔧 Stub (interface complete) | Service Token | ❌ |
| Infisical | 🔧 Stub (interface complete) | Universal Auth | ❌ |

All three satisfy the `SecretsProvider` interface and are registered in
the provider factory. The full GSoC project would complete rotation
support and add integration tests for Doppler and Infisical.

### 2. Security Hardening — JWT/OIDC Authentication

Both **HashiCorp Vault** and **OpenBao** now support two additional
authentication methods alongside the existing `token` and `approle`:

- `jwt` — authenticate using a raw JWT token
- `oidc` — authenticate using OpenID Connect

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="vault" \
    VAULT_AUTH_METHOD="jwt" \
    VAULT_JWT_TOKEN="your-jwt-token" \
    VAULT_OIDC_ROLE="your-vault-role"
```

### 3. Security Hardening — Enhanced TLS/mTLS (CABundle)

A new shared TLS helper (`providers/tls.go`) enables raw PEM-encoded CA
bundle support across all providers — no file path required. This is
practical in containerised environments where mounting files is not
feasible.

```bash
docker plugin set swarm-external-secrets:latest \
    VAULT_CA_BUNDLE="$(cat /path/to/ca-bundle.pem)"
```

CABundle + mTLS is supported for: Vault, OpenBao, 1Password, Doppler,
Infisical.

---

## New Files

| File | Description |
|---|---|
| `providers/tls.go` | Shared CABundle/mTLS helper |
| `providers/onepassword.go` | 1Password Connect provider (full) |
| `providers/doppler.go` | Doppler provider (stub) |
| `providers/infisical.go` | Infisical provider (stub) |
| `providers/onepassword_test.go` | 9 unit tests (mock HTTP server) |
| `providers/doppler_test.go` | 7 unit tests (mock HTTP server) |
| `providers/infisical_test.go` | 7 unit tests (mock HTTP server) |

## Modified Files

| File | Change |
|---|---|
| `providers/vault.go` | JWT/OIDC auth + CABundle TLS |
| `providers/openbao.go` | JWT/OIDC auth + CABundle TLS |
| `providers/factory.go` | Registered 3 new providers |
| `config.json` | Added env vars for all new providers |
| `readme.md` | Updated provider table + quick start |
| `docs/multi-provider.md` | Full config guides for new providers |

---

## Running the Tests

No external accounts or services needed — all tests use local mock HTTP
servers.

```bash
# Run all provider tests
go test ./providers/ -v

# Run only 1Password tests
go test ./providers/ -run TestOnePassword -v

# Run only Doppler tests
go test ./providers/ -run TestDoppler -v

# Run only Infisical tests
go test ./providers/ -run TestInfisical -v
```

**Current test results: 23/23 passing**

---

## Using the New Providers

### 1Password Connect

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="1password" \
    OP_CONNECT_HOST="https://my-connect-server:8080" \
    OP_CONNECT_TOKEN="your-connect-token" \
    OP_VAULT="my-vault"
```

```yaml
secrets:
  db_password:
    driver: swarm-external-secrets:latest
    labels:
      op_vault: "my-vault"
      op_item: "production-database"
      op_field: "password"
```

### Doppler

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="doppler" \
    DOPPLER_TOKEN="dp.st.your-service-token" \
    DOPPLER_PROJECT="myapp" \
    DOPPLER_CONFIG="prd"
```

```yaml
secrets:
  db_password:
    driver: swarm-external-secrets:latest
    labels:
      doppler_project: "myapp"
      doppler_config: "prd"
      doppler_name: "DB_PASSWORD"
```

### Infisical

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="infisical" \
    INFISICAL_CLIENT_ID="your-client-id" \
    INFISICAL_CLIENT_SECRET="your-client-secret" \
    INFISICAL_PROJECT_ID="your-project-id" \
    INFISICAL_ENVIRONMENT="prod"
```

```yaml
secrets:
  db_password:
    driver: swarm-external-secrets:latest
    labels:
      infisical_project: "your-project-id"
      infisical_environment: "prod"
      infisical_key: "DB_PASSWORD"
```

---

## What the Full GSoC Project Would Deliver

This prototype covers the foundational work. The complete GSoC project
would add:

- Full rotation support for Doppler and Infisical
- PushSecret capability (bidirectional secret sync)
- Smoke tests for all 3 new providers
- JWT/OIDC token refresh logic
- Prometheus metrics + structured audit logging
- Generic webhook provider for custom integrations

---

## References

- [GSoC Project Idea](https://github.com/sugar-org/swarm-external-secrets/wiki/Project-Ideas)
- [1Password Connect API](https://developer.1password.com/docs/connect/)
- [Doppler API](https://docs.doppler.com/reference/api)
- [Infisical API](https://infisical.com/docs/api-reference/overview/introduction)
- [Vault JWT/OIDC Auth](https://developer.hashicorp.com/vault/docs/auth/jwt)
- [External Secrets Operator](https://external-secrets.io/) (reference implementation)
