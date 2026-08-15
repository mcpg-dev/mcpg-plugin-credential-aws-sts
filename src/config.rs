//! Operator-supplied configuration schema for
//! `dev.mcpg.credential.aws-sts`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StsConfig {
    /// AWS region the STS client targets, e.g. `us-east-1`. The SDK
    /// requires a region even when an `endpoint_url` override points
    /// at LocalStack / a VPC endpoint.
    pub region: String,

    /// Optional STS endpoint override. Set to a LocalStack / VPC /
    /// FIPS endpoint, e.g. `http://localhost:4566` or
    /// `https://sts.us-east-1.amazonaws.com`. `None` uses the AWS
    /// default resolver for the region.
    #[serde(default)]
    pub endpoint_url: Option<String>,

    /// Base credentials the plugin uses to *call* AssumeRole. `None`
    /// (the default) uses the AWS default credential chain (the
    /// gateway's IAM role / IRSA / env / profile). Set static keys
    /// only for local testing — production deployments should run as
    /// an IAM principal whose trust policy is allowed to assume the
    /// target roles.
    #[serde(default)]
    pub base_credentials: Option<BaseCredentials>,

    /// Per-target role mapping. At least one target is required.
    pub targets: BTreeMap<String, TargetConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BaseCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    #[serde(default)]
    pub session_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TargetConfig {
    /// Role ARN to assume. Required (and validated) when
    /// `identity_mapping == "static"`. For the identity-derived modes
    /// it is the operator-fixed fallback used when the caller has no
    /// usable identity value.
    #[serde(default)]
    pub role_arn: String,

    #[serde(default)]
    pub identity_mapping: IdentityMapping,

    /// Required when `identity_mapping == "template"`. Substitution
    /// syntax: `${identity.<field>}` — fields: `subject_id`, `kind`,
    /// `trust_level`, `auth_provider`, `roles[N]`, `groups[N]`,
    /// `scopes[N]`, `attributes.<key>`. The substituted result MUST be
    /// a well-formed IAM role ARN.
    #[serde(default)]
    pub role_arn_template: Option<String>,

    /// Optional allowlist of role ARNs this target may ever assume.
    /// When `Some`, an identity-derived ARN (subject_id / first-role /
    /// template output) MUST appear in this list or the request is
    /// refused — bounding which roles a caller can select even if the
    /// upstream identity is spoofable. `None` (the default) applies no
    /// allowlist. Static mode is unaffected (the ARN is
    /// operator-fixed). Entries are validated as role ARNs at config
    /// load.
    #[serde(default)]
    pub allowed_role_arns: Option<Vec<String>>,

    /// Optional operator-fixed prefix prepended to the derived
    /// `RoleSessionName`. The session name (prefix + sanitised caller
    /// subject) is what surfaces in CloudTrail for attribution. STS
    /// requires the full name to match `[\w+=,.@-]{2,64}`; the plugin
    /// sanitises + truncates to satisfy that.
    #[serde(default)]
    pub session_name_prefix: Option<String>,

    /// Optional `ExternalId` passed to AssumeRole — the cross-account
    /// confused-deputy guard. Required by some role trust policies.
    #[serde(default)]
    pub external_id: Option<String>,

    /// Optional inline IAM session policy (JSON) that further
    /// restricts the assumed session's permissions. Bounded by AWS at
    /// 2048 characters.
    #[serde(default)]
    pub session_policy: Option<String>,

    /// Optional requested session duration in seconds. AWS bounds this
    /// to `900..=43200` and additionally caps it at the role's
    /// `MaxSessionDuration`. `None` lets STS use the role default
    /// (typically 3600s).
    #[serde(default)]
    pub duration_seconds: Option<u32>,

    /// Cap on the cache TTL for this target (milliseconds). The plugin
    /// returns `min(sts_expiry, max_cache_ttl_ms)` so the gateway's
    /// per-target cache never outlives the STS session.
    #[serde(default = "default_max_cache_ttl_ms")]
    pub max_cache_ttl_ms: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum IdentityMapping {
    /// Always assume `target.role_arn`. Default. Every caller of this
    /// target assumes the same operator-fixed role.
    #[default]
    Static,
    /// Use `identity.subject_id` directly as the role ARN. Operators
    /// whose IdP stamps the assumable ARN into the subject use this.
    SubjectId,
    /// Substitute identity fields into `target.role_arn_template`.
    Template,
    /// Use `identity.roles[0]` as the role ARN.
    FromRole,
}

const MAX_DURATION_SECONDS: u32 = 43_200;
const MIN_DURATION_SECONDS: u32 = 900;
const MAX_SESSION_POLICY_BYTES: usize = 2048;

fn default_max_cache_ttl_ms() -> u64 {
    3_600_000
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid credential.aws-sts config JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("credential.aws-sts: region is empty")]
    EmptyRegion,
    #[error("credential.aws-sts: endpoint_url must start with http:// or https://")]
    InvalidEndpointScheme,
    #[error("credential.aws-sts: base_credentials.access_key_id is empty")]
    EmptyAccessKeyId,
    #[error("credential.aws-sts: base_credentials.secret_access_key is empty")]
    EmptySecretAccessKey,
    #[error("credential.aws-sts: targets must be non-empty")]
    EmptyTargets,
    #[error(
        "credential.aws-sts: target `{name}` has identity_mapping=static but role_arn is empty"
    )]
    StaticTargetMissingArn { name: String },
    #[error(
        "credential.aws-sts: target `{name}` has identity_mapping=template but role_arn_template is missing"
    )]
    TemplateTargetMissingTemplate { name: String },
    #[error(
        "credential.aws-sts: target `{name}` role_arn `{arn}` is not a valid IAM role ARN \
         (expected arn:<partition>:iam::<account>:role/<name>)"
    )]
    InvalidRoleArn { name: String, arn: String },
    #[error(
        "credential.aws-sts: target `{name}` allowed_role_arns entry `{arn}` is not a valid IAM \
         role ARN"
    )]
    InvalidAllowedRoleArn { name: String, arn: String },
    #[error(
        "credential.aws-sts: target `{name}` duration_seconds={secs} out of range \
         (must be {MIN_DURATION_SECONDS}..={MAX_DURATION_SECONDS})"
    )]
    InvalidDuration { name: String, secs: u32 },
    #[error(
        "credential.aws-sts: target `{name}` session_policy exceeds the {MAX_SESSION_POLICY_BYTES}-byte AWS limit"
    )]
    SessionPolicyTooLarge { name: String },
    #[error("credential.aws-sts: target `{name}` session_policy is not valid JSON")]
    SessionPolicyNotJson { name: String },
    #[error(
        "credential.aws-sts: target `{name}` has max_cache_ttl_ms={ttl}; must be 1..=86_400_000 (1 ms to 1 day)"
    )]
    InvalidMaxCacheTtl { name: String, ttl: u64 },
}

impl StsConfig {
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        let cfg: Self = serde_json::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.region.trim().is_empty() {
            return Err(ConfigError::EmptyRegion);
        }
        if let Some(ep) = &self.endpoint_url
            && !ep.starts_with("http://")
            && !ep.starts_with("https://")
        {
            return Err(ConfigError::InvalidEndpointScheme);
        }
        if let Some(base) = &self.base_credentials {
            if base.access_key_id.trim().is_empty() {
                return Err(ConfigError::EmptyAccessKeyId);
            }
            if base.secret_access_key.is_empty() {
                return Err(ConfigError::EmptySecretAccessKey);
            }
        }
        if self.targets.is_empty() {
            return Err(ConfigError::EmptyTargets);
        }
        for (name, target) in &self.targets {
            match target.identity_mapping {
                IdentityMapping::Static => {
                    if target.role_arn.is_empty() {
                        return Err(ConfigError::StaticTargetMissingArn { name: name.clone() });
                    }
                    if !crate::identity_mapping::is_valid_role_arn(&target.role_arn) {
                        return Err(ConfigError::InvalidRoleArn {
                            name: name.clone(),
                            arn: target.role_arn.clone(),
                        });
                    }
                }
                IdentityMapping::Template => {
                    if target
                        .role_arn_template
                        .as_deref()
                        .map(str::is_empty)
                        .unwrap_or(true)
                    {
                        return Err(ConfigError::TemplateTargetMissingTemplate {
                            name: name.clone(),
                        });
                    }
                }
                IdentityMapping::SubjectId | IdentityMapping::FromRole => {
                    // A non-empty operator fallback is itself an ARN and
                    // must be well-formed; an empty fallback is allowed
                    // (the runtime returns NotAuthorized when the
                    // identity yields nothing).
                    if !target.role_arn.is_empty()
                        && !crate::identity_mapping::is_valid_role_arn(&target.role_arn)
                    {
                        return Err(ConfigError::InvalidRoleArn {
                            name: name.clone(),
                            arn: target.role_arn.clone(),
                        });
                    }
                }
            }
            if let Some(allow) = &target.allowed_role_arns {
                for arn in allow {
                    if !crate::identity_mapping::is_valid_role_arn(arn) {
                        return Err(ConfigError::InvalidAllowedRoleArn {
                            name: name.clone(),
                            arn: arn.clone(),
                        });
                    }
                }
            }
            if let Some(secs) = target.duration_seconds
                && !(MIN_DURATION_SECONDS..=MAX_DURATION_SECONDS).contains(&secs)
            {
                return Err(ConfigError::InvalidDuration {
                    name: name.clone(),
                    secs,
                });
            }
            if let Some(policy) = &target.session_policy {
                if policy.len() > MAX_SESSION_POLICY_BYTES {
                    return Err(ConfigError::SessionPolicyTooLarge { name: name.clone() });
                }
                if serde_json::from_str::<serde_json::Value>(policy).is_err() {
                    return Err(ConfigError::SessionPolicyNotJson { name: name.clone() });
                }
            }
            if target.max_cache_ttl_ms == 0 || target.max_cache_ttl_ms > 86_400_000 {
                return Err(ConfigError::InvalidMaxCacheTtl {
                    name: name.clone(),
                    ttl: target.max_cache_ttl_ms,
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn minimal() -> serde_json::Value {
        json!({
            "region": "us-east-1",
            "targets": {
                "orders-ro": {
                    "role_arn": "arn:aws:iam::123456789012:role/orders-readonly"
                }
            }
        })
    }

    #[test]
    fn parses_minimal() {
        let cfg = StsConfig::parse(&minimal().to_string()).unwrap();
        assert_eq!(cfg.region, "us-east-1");
        assert_eq!(cfg.targets.len(), 1);
        let t = &cfg.targets["orders-ro"];
        assert_eq!(t.identity_mapping, IdentityMapping::Static);
        assert_eq!(t.max_cache_ttl_ms, 3_600_000);
    }

    #[test]
    fn rejects_empty_region() {
        let mut v = minimal();
        v["region"] = json!("");
        assert!(matches!(
            StsConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::EmptyRegion
        ));
    }

    #[test]
    fn rejects_unknown_field() {
        let mut v = minimal();
        v["bogus"] = json!(true);
        assert!(matches!(
            StsConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidJson(_)
        ));
    }

    #[test]
    fn rejects_bad_endpoint_scheme() {
        let mut v = minimal();
        v["endpoint_url"] = json!("ftp://sts.local");
        assert!(matches!(
            StsConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidEndpointScheme
        ));
    }

    #[test]
    fn rejects_static_without_arn() {
        let mut v = minimal();
        v["targets"]["orders-ro"]["role_arn"] = json!("");
        assert!(matches!(
            StsConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::StaticTargetMissingArn { .. }
        ));
    }

    #[test]
    fn rejects_static_with_malformed_arn() {
        let mut v = minimal();
        v["targets"]["orders-ro"]["role_arn"] = json!("not-an-arn");
        assert!(matches!(
            StsConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidRoleArn { .. }
        ));
    }

    #[test]
    fn rejects_template_without_template() {
        let mut v = minimal();
        v["targets"]["orders-ro"] = json!({
            "identity_mapping": "template"
        });
        assert!(matches!(
            StsConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::TemplateTargetMissingTemplate { .. }
        ));
    }

    #[test]
    fn rejects_bad_allowlist_entry() {
        let mut v = minimal();
        v["targets"]["orders-ro"]["identity_mapping"] = json!("subject_id");
        v["targets"]["orders-ro"]["allowed_role_arns"] =
            json!(["arn:aws:iam::123456789012:role/ok", "garbage"]);
        assert!(matches!(
            StsConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidAllowedRoleArn { .. }
        ));
    }

    #[test]
    fn rejects_out_of_range_duration() {
        let mut v = minimal();
        v["targets"]["orders-ro"]["duration_seconds"] = json!(60);
        assert!(matches!(
            StsConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidDuration { .. }
        ));
    }

    #[test]
    fn accepts_in_range_duration() {
        let mut v = minimal();
        v["targets"]["orders-ro"]["duration_seconds"] = json!(3600);
        assert!(StsConfig::parse(&v.to_string()).is_ok());
    }

    #[test]
    fn rejects_non_json_session_policy() {
        let mut v = minimal();
        v["targets"]["orders-ro"]["session_policy"] = json!("{not json");
        assert!(matches!(
            StsConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::SessionPolicyNotJson { .. }
        ));
    }

    #[test]
    fn rejects_zero_ttl() {
        let mut v = minimal();
        v["targets"]["orders-ro"]["max_cache_ttl_ms"] = json!(0);
        assert!(matches!(
            StsConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidMaxCacheTtl { .. }
        ));
    }

    #[test]
    fn rejects_empty_access_key() {
        let mut v = minimal();
        v["base_credentials"] = json!({"access_key_id": "", "secret_access_key": "x"});
        assert!(matches!(
            StsConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::EmptyAccessKeyId
        ));
    }

    #[test]
    fn base_credentials_roundtrip() {
        let mut v = minimal();
        v["base_credentials"] = json!({
            "access_key_id": "AKIA_TEST",
            "secret_access_key": "secret",
            "session_token": "tok"
        });
        let cfg = StsConfig::parse(&v.to_string()).unwrap();
        let base = cfg.base_credentials.unwrap();
        assert_eq!(base.access_key_id, "AKIA_TEST");
        assert_eq!(base.session_token.as_deref(), Some("tok"));
    }
}
