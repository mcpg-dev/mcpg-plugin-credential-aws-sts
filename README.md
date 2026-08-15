# AWS STS AssumeRole Credentials (`dev.mcpg.credential.aws-sts`)

A **credential_issuer** plugin that mints **short-lived AWS
credentials per request** via STS [`AssumeRole`]. The gateway runs as a
base IAM principal (its IRSA / instance role, or operator-supplied
static keys) and assumes a **target role** chosen by mapping the
caller's `PluginIdentity`. The caller's subject is stamped into the
`RoleSessionName`, so every assumed-role action is attributable to the
real caller in CloudTrail.

Binding plugins consume the issued credential through the `cred://`
scheme, authenticating to AWS as the per-caller-scoped role rather than
as one shared service account.

## How it differs from web-identity federation

This plugin uses **`AssumeRole`** — the gateway's base principal
assumes the target role and re-stamps the caller's subject as the
session name. It does **not** forward the caller's own OIDC token to
AWS. That keeps the trust model simple (AWS trusts the gateway's
principal; the role's trust policy + an optional session policy bound
the grant) and is the standard server-side pattern.
`AssumeRoleWithWebIdentity` (federating the caller's own token) is a
planned opt-in follow-up.

## Configuration

| Field | Type | Default | Description |
|---|---|---|---|
| `region` | string | *(required)* | AWS region for the STS client. |
| `endpoint_url` | string | *(none)* | STS endpoint override (LocalStack / VPC / FIPS). Must be `http(s)://`. |
| `base_credentials` | object | *(none → default chain)* | Static keys the plugin uses to *call* AssumeRole. Production should omit this and run as an IAM principal (IRSA / instance role). |
| `targets` | map | *(required, ≥1)* | Per-target role mapping (see below). |

`base_credentials`: `{ access_key_id, secret_access_key, session_token? }`.

### Target

| Field | Type | Default | Description |
|---|---|---|---|
| `role_arn` | string | `""` | Role to assume. Required + validated for `static`; the operator-fixed fallback otherwise. |
| `identity_mapping` | `static` \| `subject_id` \| `from_role` \| `template` | `static` | How the role ARN is chosen. |
| `role_arn_template` | string | *(none)* | Required for `template`. `${identity.<field>}` placeholders; result must be a role ARN. |
| `allowed_role_arns` | array | *(none)* | Allowlist bounding which ARNs an identity-derived mapping may assume. |
| `session_name_prefix` | string | *(none)* | Prefix prepended to the derived `RoleSessionName`. |
| `external_id` | string | *(none)* | `ExternalId` for cross-account confused-deputy protection. |
| `session_policy` | string (JSON) | *(none)* | Inline IAM session policy further restricting the session (≤2048 chars). |
| `duration_seconds` | int | *(role default)* | Requested session duration; AWS bounds to `900..=43200` and the role's max. |
| `max_cache_ttl_ms` | int | `3600000` | Cap on the gateway cache TTL; effective TTL is `min(sts_expiry, this)`. |

### Identity mapping

- **`static`** — every caller assumes `role_arn` (operator-fixed).
- **`subject_id`** — the caller's `subject_id` is the role ARN.
- **`from_role`** — `identity.roles[0]` is the role ARN.
- **`template`** — substitute identity fields into `role_arn_template`,
  e.g. `arn:aws:iam::123456789012:role/mcpg-${identity.attributes.team}`.

**Security floor:** any role ARN derived from caller-controlled
identity (`subject_id` / `from_role` / `template`) is only honoured for
a **Verified** principal — header-asserted / unauthenticated callers
are refused (`NotAuthorized`). The resolved ARN must also be a
well-formed IAM role ARN and, if `allowed_role_arns` is set, appear in
it. Static / fallback ARNs are operator-fixed and exempt.

## Example

```yaml
# Load the credential-issuer plugin (top-level `plugins:` is a flat list).
plugins:
  - id: dev.mcpg.credential.aws-sts
    class: credential_issuer
    source: { oci: "oci://ghcr.io/mcpg-dev/plugins/credential-aws-sts:protocol-1" }
    config:
      region: us-east-1
      targets:
        analytics-ro:
          role_arn: "arn:aws:iam::123456789012:role/analytics-readonly"
        per-team:
          identity_mapping: template
          role_arn_template: "arn:aws:iam::123456789012:role/mcpg-${identity.attributes.team}"
          allowed_role_arns:
            - "arn:aws:iam::123456789012:role/mcpg-platform"
            - "arn:aws:iam::123456789012:role/mcpg-data"
          session_name_prefix: mcpg
          duration_seconds: 3600
```

A binding then consumes the issued credential through the `cred://` scheme
(`cred://<plugin-id>/<target>`) in any config-origin position — e.g. a tool
whose `backend` authenticates to AWS with the assumed creds. The marker is
resolved per-request against the caller's identity.

## Issued credential

`parts`: `access_key_id`, `secret_access_key`, `session_token`.
`ttl_seconds` is the STS session remaining time, capped at
`max_cache_ttl_ms`. `lease_id` is absent — STS sessions can't be
individually revoked; `revoke` is a no-op and the session expires on
its own.

## Testing

Unit tests (`cargo test -p mcpg-plugin-credential-aws-sts --lib`) cover
config validation, identity→ARN mapping, the Verified-trust /
ARN-shape / allowlist guards, and TTL capping — all offline. A
LocalStack-backed integration suite exercises a real AssumeRole
round-trip:

```bash
cargo test -p mcpg-plugin-credential-aws-sts --features integration-tests --test integration
```

(needs Docker; runs in the `--config=integration` CI lane.)

## Notes

- Pure-Rust, rustls-only: the AWS SDK uses the modern
  `default-https-client` (aws-lc-rs / rustls 0.23) — **not** the legacy
  `rustls` feature.
- `network_outbound` capability (reaches the STS endpoint).
- The session name is attribution metadata, not an authorization
  boundary — the assumed role's trust + session policy define the
  actual grants.

[`AssumeRole`]: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
