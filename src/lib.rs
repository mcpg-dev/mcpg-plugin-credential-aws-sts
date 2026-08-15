//! `dev.mcpg.credential.aws-sts` — `credential_issuer` plugin.
//!
//! Issues short-lived AWS credentials per request via STS
//! `AssumeRole`. The gateway runs as a base IAM principal (its IRSA /
//! instance role, or operator-supplied static keys); this plugin maps
//! the caller's `PluginIdentity` to a target role ARN per
//! operator-configurable rules and assumes it, stamping the caller's
//! subject into the `RoleSessionName` so the assumed-role activity is
//! attributable in CloudTrail. The gateway's per-(identity, plugin,
//! target) cache holds the credential for
//! `min(sts_session_remaining, max_cache_ttl_ms / 1000)` (floored at
//! 1s) so steady-state AssumeRole load stays low.
//!
//! # Scope
//!
//! - **AssumeRole** with caller-stamped `RoleSessionName`, optional
//!   `ExternalId`, inline session policy, and requested duration.
//! - **Identity mapping**: static, subject_id, from_role, template —
//!   identity-derived role ARNs require Verified trust + pass an ARN
//!   shape check + optional per-target allowlist.
//! - **Base credentials**: the default AWS chain (IRSA / instance role
//!   / env / profile) or operator-supplied static keys (local/testing).
//! - **No revocation**: STS sessions can't be individually revoked;
//!   they auto-expire. `revoke` is a no-op (cache eviction just drops
//!   the cached credential).
//!
//! `AssumeRoleWithWebIdentity` (federating a caller's own OIDC token to
//! AWS instead of re-stamping it onto the gateway's session) is a
//! deferred follow-up.

mod config;
mod identity_mapping;
mod sts_client;

use std::sync::Arc;

use async_trait::async_trait;
use mcpg_plugin_protocol::credential::{CredentialError, CredentialIssuer, IssuedCredential};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{PluginClass, PluginManifest};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncCredentialIssuer;
use serde_json::Value;
use tokio::runtime::Runtime;

pub use config::{BaseCredentials, ConfigError, IdentityMapping, StsConfig, TargetConfig};

const PLUGIN_ID: &str = "dev.mcpg.credential.aws-sts";

pub struct AwsStsPlugin {
    inner: Arc<Inner>,
}

struct Inner {
    manifest: PluginManifest,
    config: StsConfig,
    client: sts_client::StsClient,
    runtime: Runtime,
}

impl AwsStsPlugin {
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg = StsConfig::parse(config_json).unwrap_or_else(|err| {
            tracing::error!(
                plugin_id = PLUGIN_ID,
                error = %err,
                "aws-sts: config parse failed; refusing to register"
            );
            panic!(
                "aws-sts config parse failed: {err}. A misconfigured credential \
                 issuer is a security hole; refusing to load."
            )
        });
        Self::from_validated_config(cfg)
    }

    fn from_validated_config(cfg: StsConfig) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("aws-sts: failed to build tokio runtime");
        let client = runtime.block_on(sts_client::StsClient::new(&cfg));
        tracing::info!(
            plugin_id = PLUGIN_ID,
            region = %cfg.region,
            target_count = cfg.targets.len(),
            "aws-sts: configured"
        );
        Self {
            inner: Arc::new(Inner {
                manifest: PluginManifest {
                    id: PLUGIN_ID.into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    name: "AWS STS AssumeRole Credentials".into(),
                    plugin_class: PluginClass::CredentialIssuer,
                    protocol_version: "1.0".into(),
                    license: None,
                    required_capabilities: Vec::new(),
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: Vec::new(),
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                },
                config: cfg,
                client,
                runtime,
            }),
        }
    }
}

async fn issue_inner(
    inner: &Inner,
    identity: &PluginIdentity,
    target: &str,
) -> Result<IssuedCredential, CredentialError> {
    let target_cfg =
        inner
            .config
            .targets
            .get(target)
            .ok_or_else(|| CredentialError::Misconfigured {
                reason: format!("unknown target: {target}"),
            })?;

    let role_arn = match identity_mapping::resolve_role(identity, target_cfg) {
        identity_mapping::Resolution::Role {
            arn,
            identity_derived,
        } => {
            // A role ARN driven by caller-controlled identity (subject_id
            // / first-role / template) must come from a Verified
            // principal. Header-asserted / unauthenticated identities are
            // spoofable and must not steer which AWS role — and thus
            // which cloud permissions — the caller assumes. Static and
            // operator-fallback ARNs are exempt (operator-fixed).
            if identity_derived && identity.trust_level != "verified" {
                metric_issue(target, "untrusted_identity");
                return Err(CredentialError::NotAuthorized {
                    reason: format!(
                        "identity-derived role ARN requires Verified trust; caller trust is `{}`",
                        identity.trust_level
                    ),
                });
            }
            // The ARN is handed straight to STS AssumeRole; reject
            // anything that isn't a well-formed IAM role ARN so a crafted
            // identity can't steer the call to an arbitrary principal.
            if !identity_mapping::is_valid_role_arn(&arn) {
                metric_issue(target, "invalid_role_arn");
                return Err(CredentialError::NotAuthorized {
                    reason: "resolved value is not a valid IAM role ARN".into(),
                });
            }
            // Optional per-target allowlist bounds which ARNs this target
            // may ever assume.
            if let Some(allow) = &target_cfg.allowed_role_arns
                && !allow.iter().any(|a| a == &arn)
            {
                metric_issue(target, "arn_not_allowed");
                return Err(CredentialError::NotAuthorized {
                    reason: "resolved role ARN is not in this target's allowed_role_arns".into(),
                });
            }
            arn
        }
        identity_mapping::Resolution::EmptyDerived { reason } => {
            metric_issue(target, "empty_identity");
            return Err(CredentialError::NotAuthorized { reason });
        }
        identity_mapping::Resolution::SubstitutionFailed { field } => {
            metric_issue(target, "substitution_failed");
            return Err(CredentialError::NotAuthorized {
                reason: format!(
                    "identity template substitution failed: field `{field}` is None or out-of-bounds"
                ),
            });
        }
    };

    let session_name = identity_mapping::session_name(
        identity.subject_id.as_deref(),
        target_cfg.session_name_prefix.as_deref(),
    );

    let req = sts_client::AssumeRequest {
        role_arn: &role_arn,
        session_name: &session_name,
        duration_seconds: target_cfg.duration_seconds.map(|d| d as i32),
        external_id: target_cfg.external_id.as_deref(),
        session_policy: target_cfg.session_policy.as_deref(),
    };

    let started = std::time::Instant::now();
    let creds = inner.client.assume_role(&req).await?;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    metrics::histogram!(
        "mcpg_aws_sts_assume_latency_ms",
        "target" => target.to_owned(),
    )
    .record(elapsed_ms as f64);
    metric_issue(target, "ok");

    let ttl = cap_ttl_seconds(creds.expiry_secs, target_cfg.max_cache_ttl_ms);
    let mut metadata = std::collections::BTreeMap::new();
    metadata.insert("aws.role_arn".to_string(), role_arn);
    metadata.insert("aws.session_name".to_string(), session_name);
    if let Some(id) = creds.assumed_role_id {
        metadata.insert("aws.assumed_role_id".to_string(), id);
    }
    if let Some(arn) = creds.assumed_role_arn {
        metadata.insert("aws.assumed_role_arn".to_string(), arn);
    }

    Ok(IssuedCredential {
        value: None,
        parts: [
            ("access_key_id".to_string(), creds.access_key_id),
            ("secret_access_key".to_string(), creds.secret_access_key),
            ("session_token".to_string(), creds.session_token),
        ]
        .into_iter()
        .collect(),
        ttl_seconds: ttl,
        // STS sessions have no per-session revocation API; they expire on
        // their own. No lease handle to return.
        lease_id: None,
        issued_at: now_rfc3339(),
        metadata,
    })
}

fn metric_issue(target: &str, result: &str) {
    metrics::counter!(
        "mcpg_aws_sts_issue_total",
        "target" => target.to_owned(),
        "result" => result.to_owned(),
    )
    .increment(1);
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Cap the cached credential TTL (seconds) at the operator's
/// millisecond limit. `max_cache_ttl_ms` is in milliseconds while the
/// STS expiry and the host cache both work in seconds, so convert
/// before clamping, with a 1-second floor so a sub-second cap never
/// yields a 0s TTL (instant expiry).
fn cap_ttl_seconds(expiry_secs: u64, max_cache_ttl_ms: u64) -> u64 {
    (max_cache_ttl_ms / 1000).max(1).min(expiry_secs)
}

#[async_trait]
impl CredentialIssuer for AwsStsPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    async fn issue(
        &self,
        identity: &PluginIdentity,
        target: &str,
        _config: &Value,
    ) -> Result<IssuedCredential, CredentialError> {
        issue_inner(&self.inner, identity, target).await
    }

    async fn revoke(&self, _lease_id: &str) -> Result<(), CredentialError> {
        // STS temporary credentials cannot be individually revoked; they
        // expire at their session deadline. Cache eviction simply drops
        // the cached copy.
        Ok(())
    }
}

impl SyncCredentialIssuer for AwsStsPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn issue(
        &self,
        identity: &PluginIdentity,
        target: &str,
        _config: &Value,
    ) -> Result<IssuedCredential, CredentialError> {
        let inner = Arc::clone(&self.inner);
        let identity = identity.clone();
        let target = target.to_owned();
        self.inner
            .runtime
            .block_on(async move { issue_inner(&inner, &identity, &target).await })
    }

    fn revoke(&self, _lease_id: &str) -> Result<(), CredentialError> {
        Ok(())
    }
}

declare_plugin! {
    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    entities: [
        credential_issuer as entity {
            inner_name: "",
            plugin_type: AwsStsPlugin,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| -> AwsStsPlugin {
                AwsStsPlugin::from_config_json(cfg)
            },
        }
    ],
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ARN_RO: &str = "arn:aws:iam::123456789012:role/orders-readonly";

    #[test]
    fn cap_ttl_clamps_long_session() {
        assert_eq!(cap_ttl_seconds(3600, 60_000), 60);
    }

    #[test]
    fn cap_ttl_uses_session_when_below_cap() {
        assert_eq!(cap_ttl_seconds(45, 3_600_000), 45);
    }

    #[test]
    fn cap_ttl_sub_second_cap_floors_to_one() {
        assert_eq!(cap_ttl_seconds(3600, 500), 1);
    }

    fn identity(trust: &str, subject: &str) -> PluginIdentity {
        PluginIdentity {
            kind: trust.to_owned(),
            trust_level: trust.to_owned(),
            subject_id: Some(subject.to_owned()),
            auth_provider: Some("okta".into()),
            issuer: Some("https://okta.example.com".into()),
            roles: vec![],
            groups: vec![],
            scopes: vec![],
            attributes: std::collections::BTreeMap::new(),
        }
    }

    fn plugin_with_subject_target(allowed: Option<Vec<&str>>) -> AwsStsPlugin {
        let mut target = json!({
            "role_arn": ARN_RO,
            "identity_mapping": "subject_id"
        });
        if let Some(a) = allowed {
            target["allowed_role_arns"] = json!(a);
        }
        let cfg = json!({
            "region": "us-east-1",
            // Static base creds so construction never probes IMDS/SSO and
            // stays fully offline — these tests assert the identity guards
            // that return BEFORE any STS call.
            "base_credentials": {"access_key_id": "AKIA_TEST", "secret_access_key": "secret"},
            "targets": { "t": target }
        });
        AwsStsPlugin::from_config_json(&cfg.to_string())
    }

    #[test]
    fn from_config_json_succeeds_with_static_target() {
        let cfg = json!({
            "region": "us-east-1",
            "base_credentials": {"access_key_id": "AKIA_TEST", "secret_access_key": "secret"},
            "targets": { "ro": {"role_arn": ARN_RO} }
        });
        let plugin = AwsStsPlugin::from_config_json(&cfg.to_string());
        assert_eq!(plugin.inner.manifest.id, PLUGIN_ID);
        assert_eq!(
            plugin.inner.manifest.plugin_class,
            PluginClass::CredentialIssuer
        );
        assert_eq!(plugin.inner.config.targets.len(), 1);
    }

    #[test]
    #[should_panic(expected = "aws-sts config parse failed")]
    fn malformed_config_panics_at_construction() {
        AwsStsPlugin::from_config_json("{ not json");
    }

    #[test]
    #[should_panic(expected = "aws-sts config parse failed")]
    fn empty_targets_panics_at_construction() {
        let bad = json!({ "region": "us-east-1", "targets": {} });
        AwsStsPlugin::from_config_json(&bad.to_string());
    }

    // ----- identity-derived ARN guards (return before any STS call, so
    // these are deterministic + offline) -----

    #[test]
    fn issue_rejects_identity_derived_arn_from_unverified_caller() {
        let plugin = plugin_with_subject_target(None);
        let err = SyncCredentialIssuer::issue(
            &plugin,
            // a spoofable header-asserted caller whose subject is a valid
            // ARN — must still be refused before the STS call.
            &identity("header_asserted", "arn:aws:iam::123456789012:role/admin"),
            "t",
            &Value::Null,
        )
        .expect_err("unverified identity-derived ARN must be refused");
        assert!(
            matches!(err, CredentialError::NotAuthorized { ref reason } if reason.contains("Verified trust")),
            "{err:?}"
        );
    }

    #[test]
    fn issue_rejects_non_arn_subject() {
        let plugin = plugin_with_subject_target(None);
        let err = SyncCredentialIssuer::issue(
            &plugin,
            &identity("verified", "not-an-arn"),
            "t",
            &Value::Null,
        )
        .expect_err("a non-ARN subject must be refused");
        assert!(
            matches!(err, CredentialError::NotAuthorized { ref reason } if reason.contains("valid IAM role ARN")),
            "{err:?}"
        );
    }

    #[test]
    fn issue_rejects_arn_outside_allowlist() {
        let plugin =
            plugin_with_subject_target(Some(vec!["arn:aws:iam::123456789012:role/only-this"]));
        let err = SyncCredentialIssuer::issue(
            &plugin,
            &identity("verified", "arn:aws:iam::123456789012:role/something-else"),
            "t",
            &Value::Null,
        )
        .expect_err("ARN outside allowlist must be refused");
        assert!(
            matches!(err, CredentialError::NotAuthorized { ref reason } if reason.contains("allowed_role_arns")),
            "{err:?}"
        );
    }

    #[test]
    fn issue_rejects_unknown_target() {
        let plugin = plugin_with_subject_target(None);
        let err = SyncCredentialIssuer::issue(
            &plugin,
            &identity("verified", ARN_RO),
            "no-such-target",
            &Value::Null,
        )
        .expect_err("unknown target must be refused");
        assert!(
            matches!(err, CredentialError::Misconfigured { ref reason } if reason.contains("unknown target")),
            "{err:?}"
        );
    }

    #[test]
    fn revoke_is_noop_ok() {
        let plugin = plugin_with_subject_target(None);
        assert!(SyncCredentialIssuer::revoke(&plugin, "any-lease").is_ok());
    }
}
