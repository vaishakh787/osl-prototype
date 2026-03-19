# swarm-external-secrets
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sugar-org/swarm-external-secrets/badge)](https://scorecard.dev/viewer/?uri=github.com/sugar-org/swarm-external-secrets) ![Discord](https://img.shields.io/discord/1476983394977054740?logo=discord&color=blue) [![Join our Discord](https://img.shields.io/badge/Discord-Join%20Server-5865F2?logo=discord&logoColor=white)](https://discord.gg/4NYdBu7bZy)

A Docker Swarm secrets plugin that integrates with multiple secret management providers including HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, and OpenBao.

## GSoC 2026 Prototype

This branch (`osl-prototype`) is a prototype implementation for the Google Summer of Code 2026 project idea, "Implement Enterprise Security & Provider Ecosystem Expansion," under [OpenScienceLabs](http://opensciencelabs.org/).

For contribution details, see [GSoC Contribution Guidelines](./CONTRIBUTING.md#google-summer-of-code-2026).

## Architecture

<img width="552" height="495" alt="image" src="https://github.com/user-attachments/assets/d8a51dec-23ff-461d-aae1-cb3e0ed2db1b" />


## Documentation

Please refer to the [docs](https://sugar-org.github.io/swarm-external-secrets/) for more information.

Additional local guides:

- [`docs/multi-provider.md`](./docs/multi-provider.md)
- [`docs/monitoring.md`](./docs/monitoring.md)
- [`docs/rotation.md`](./docs/rotation.md)
- [`docs/debugging.md`](./docs/debugging.md)

## What This Prototype Demonstrates

This prototype extends `swarm-external-secrets` with three major workstreams from the GSoC proposal:

### 1. New Provider Integrations

Three additional secret backends have been added alongside the existing providers:

| Provider | Status | Auth Method | Rotation |
|---|---|---|---|
| 1Password Connect | Full implementation | Connect API Token | Yes |
| Doppler | Stub (interface complete) | Service Token | No |
| Infisical | Stub (interface complete) | Universal Auth | No |

All three providers satisfy the `SecretsProvider` interface and are registered in the provider factory.

### 2. Security Hardening: JWT/OIDC Authentication

Both HashiCorp Vault and OpenBao now support two additional authentication methods alongside the existing `token` and `approle` flows:

- `jwt` for raw JWT token authentication
- `oidc` for OpenID Connect authentication

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="vault" \
    VAULT_AUTH_METHOD="jwt" \
    VAULT_JWT_TOKEN="your-jwt-token" \
    VAULT_OIDC_ROLE="your-vault-role"
```

### 3. Security Hardening: Enhanced TLS/mTLS (CA Bundle)

A shared TLS helper in `providers/tls.go` enables raw PEM-encoded CA bundle support across providers, without requiring a mounted file path.

```bash
docker plugin set swarm-external-secrets:latest \
    VAULT_CA_BUNDLE="$(cat /path/to/ca-bundle.pem)"
```

CA bundle and mTLS support is available for Vault, OpenBao, 1Password, Doppler, and Infisical.

## Features

- Multi-provider support across Vault, AWS, GCP, Azure, OpenBao, 1Password, Doppler, and Infisical
- Multiple authentication methods per provider
- Automatic secret rotation for supported providers
- Flexible path mapping and field extraction
- Backward compatibility for existing Vault configurations

## Supported Providers

| Provider | Status | Authentication | Rotation |
|---|---|---|---|
| HashiCorp Vault | Stable | Token, AppRole, JWT, OIDC | Yes |
| AWS Secrets Manager | Stable | IAM, Access Keys, Profiles | Yes |
| GCP Secret Manager | Stable | Service Account, ADC | Yes |
| Azure Key Vault | Stable | Service Principal, Managed Identity | Yes |
| OpenBao | Stable | Token, AppRole, JWT, OIDC | Yes |
| 1Password Connect | Prototype | Connect API Token | Yes |
| Doppler | Prototype | Service Token | No |
| Infisical | Prototype | Universal Auth | No |

## Multi-Provider Configuration

Select the provider with `SECRETS_PROVIDER`:

```bash
# HashiCorp Vault (default)
docker plugin set swarm-external-secrets:latest SECRETS_PROVIDER="vault"

# AWS Secrets Manager
docker plugin set swarm-external-secrets:latest SECRETS_PROVIDER="aws"

# GCP Secret Manager
docker plugin set swarm-external-secrets:latest SECRETS_PROVIDER="gcp"

# Azure Key Vault
docker plugin set swarm-external-secrets:latest SECRETS_PROVIDER="azure"

# OpenBao
docker plugin set swarm-external-secrets:latest SECRETS_PROVIDER="openbao"

# 1Password Connect
docker plugin set swarm-external-secrets:latest SECRETS_PROVIDER="1password"

# Doppler
docker plugin set swarm-external-secrets:latest SECRETS_PROVIDER="doppler"

# Infisical
docker plugin set swarm-external-secrets:latest SECRETS_PROVIDER="infisical"
```

For multi-instance usage, see [`docs/multi-provider.md`](./docs/multi-provider.md).

## Installation

1. Build and enable the plugin:

```bash
./scripts/build.sh
```

2. Configure the plugin:

```bash
docker plugin set swarm-external-secrets:latest \
    VAULT_ADDR="https://your-vault-server:8200" \
    VAULT_AUTH_METHOD="token" \
    VAULT_TOKEN="your-vault-token" \
    ENABLE_ROTATION="true"
```

3. Use it in `docker-compose.yml`:

```yaml
secrets:
  mysql_password:
    driver: swarm-external-secrets:latest
    labels:
      vault_path: "database/mysql"
      vault_field: "password"
```

## Provider Examples

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

## Test Status

No external accounts or services are needed for the new provider tests; they use local mock HTTP servers.

```bash
go test ./providers/ -v
go test ./providers/ -run TestOnePassword -v
go test ./providers/ -run TestDoppler -v
go test ./providers/ -run TestInfisical -v
```

Current prototype test status: 23/23 passing.

## Files Added or Updated

New files:

- `providers/tls.go`
- `providers/onepassword.go`
- `providers/doppler.go`
- `providers/infisical.go`
- `providers/onepassword_test.go`
- `providers/doppler_test.go`
- `providers/infisical_test.go`

Modified files:

- `providers/vault.go`
- `providers/openbao.go`
- `providers/factory.go`
- `config.json`
- `README.md`
- `docs/multi-provider.md`

## Future GSoC Scope

This prototype covers the foundation. A fuller GSoC implementation would add:

- Rotation support for Doppler and Infisical
- PushSecret capability for bidirectional secret sync
- Smoke tests for all newly added providers
- JWT/OIDC token refresh logic
- Prometheus metrics and structured audit logging
- A generic webhook provider for custom integrations

## References

- [GSoC Project Idea](https://github.com/sugar-org/swarm-external-secrets/wiki/Project-Ideas)
- [1Password Connect API](https://developer.1password.com/docs/connect/)
- [Doppler API](https://docs.doppler.com/reference/api)
- [Infisical API](https://infisical.com/docs/api-reference/overview/introduction)
- [Vault JWT/OIDC Auth](https://developer.hashicorp.com/vault/docs/auth/jwt)
- [External Secrets Operator](https://external-secrets.io/)

## License

[BSD-3-Clause license](https://github.com/sugar-org/swarm-external-secrets/blob/main/LICENSE)
