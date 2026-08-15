//! Thin async wrapper over the AWS STS `AssumeRole` API.
//!
//! Constructed once at plugin load; each `issue` call performs one
//! `AssumeRole`. The cdylib FFI boundary is sync, so the plugin bundles
//! a private tokio runtime and `block_on`s this module's async methods.

use aws_config::{BehaviorVersion, Region};
use aws_credential_types::Credentials;
use aws_sdk_sts::Client;
use aws_sdk_sts::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_sts::operation::assume_role::AssumeRoleError;
use mcpg_plugin_protocol::credential::CredentialError;

use crate::config::StsConfig;

/// Parameters for a single `AssumeRole` call.
pub(crate) struct AssumeRequest<'a> {
    pub role_arn: &'a str,
    pub session_name: &'a str,
    pub duration_seconds: Option<i32>,
    pub external_id: Option<&'a str>,
    pub session_policy: Option<&'a str>,
}

/// The temporary credentials AssumeRole returns.
pub(crate) struct AssumedCreds {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    /// Seconds from now until the STS session expires (>= 1).
    pub expiry_secs: u64,
    pub assumed_role_id: Option<String>,
    pub assumed_role_arn: Option<String>,
}

pub(crate) struct StsClient {
    client: Client,
}

impl StsClient {
    /// Build the STS client from the operator config. Loading the
    /// default credential chain is async (it may probe IMDS / SSO /
    /// profile sources), so this is async and the plugin `block_on`s it
    /// once at construction.
    pub(crate) async fn new(cfg: &StsConfig) -> Self {
        let mut loader =
            aws_config::defaults(BehaviorVersion::latest()).region(Region::new(cfg.region.clone()));

        if let Some(base) = &cfg.base_credentials {
            loader = loader.credentials_provider(Credentials::new(
                base.access_key_id.clone(),
                base.secret_access_key.clone(),
                base.session_token.clone(),
                None,
                "mcpg-sts-base",
            ));
        }
        if let Some(endpoint) = &cfg.endpoint_url {
            loader = loader.endpoint_url(endpoint.clone());
        }

        let shared = loader.load().await;
        Self {
            client: Client::new(&shared),
        }
    }

    pub(crate) async fn assume_role(
        &self,
        req: &AssumeRequest<'_>,
    ) -> Result<AssumedCreds, CredentialError> {
        let mut call = self
            .client
            .assume_role()
            .role_arn(req.role_arn)
            .role_session_name(req.session_name);
        if let Some(d) = req.duration_seconds {
            call = call.duration_seconds(d);
        }
        if let Some(e) = req.external_id {
            call = call.external_id(e);
        }
        if let Some(p) = req.session_policy {
            call = call.policy(p);
        }

        let out = match call.send().await {
            Ok(o) => o,
            Err(err) => return Err(classify_sdk_error(err)),
        };

        let creds = out.credentials().ok_or_else(|| CredentialError::Backend {
            reason: "STS AssumeRole returned no credentials".into(),
        })?;

        // STS hands back an absolute expiry; the cache wants a relative
        // TTL. Clamp at 1s so a clock that's a hair behind never yields a
        // zero-second (instant-expiry) credential.
        let now = chrono::Utc::now().timestamp();
        let expiry_secs = (creds.expiration().secs() - now).max(1) as u64;

        let (assumed_role_id, assumed_role_arn) = out
            .assumed_role_user()
            .map(|u| {
                (
                    Some(u.assumed_role_id().to_owned()),
                    Some(u.arn().to_owned()),
                )
            })
            .unwrap_or((None, None));

        Ok(AssumedCreds {
            access_key_id: creds.access_key_id().to_owned(),
            secret_access_key: creds.secret_access_key().to_owned(),
            session_token: creds.session_token().to_owned(),
            expiry_secs,
            assumed_role_id,
            assumed_role_arn,
        })
    }
}

/// Map an STS SDK error onto the credential-issuer error taxonomy. A
/// modeled service error carries an AWS error `code`; transport /
/// dispatch failures (endpoint unreachable, timeout) have none and map
/// to `Backend`.
fn classify_sdk_error(err: SdkError<AssumeRoleError>) -> CredentialError {
    let svc = err.as_service_error();
    let code = svc.and_then(|e| e.code()).unwrap_or_default().to_owned();
    let reason = svc
        .and_then(|e| e.message())
        .map(str::to_owned)
        .unwrap_or_else(|| err.to_string());
    match code.as_str() {
        "AccessDenied" | "AccessDeniedException" => CredentialError::NotAuthorized { reason },
        "Throttling"
        | "ThrottlingException"
        | "RequestLimitExceeded"
        | "TooManyRequestsException" => CredentialError::Throttled { reason },
        _ => CredentialError::Backend {
            reason: if code.is_empty() {
                reason
            } else {
                format!("STS AssumeRole [{code}]: {reason}")
            },
        },
    }
}
