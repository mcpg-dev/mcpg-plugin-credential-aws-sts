//! Identity → IAM role ARN resolution for
//! `dev.mcpg.credential.aws-sts`.

use mcpg_plugin_protocol::types::PluginIdentity;

use crate::config::{IdentityMapping, TargetConfig};

/// Resolution outcome. The error variants surface as
/// `CredentialError::NotAuthorized` so the caller (the gateway's
/// resolver) treats "this identity can't assume a role" as an
/// authorization failure rather than a backend error.
#[derive(Debug)]
pub(crate) enum Resolution {
    /// Assume this role ARN. `identity_derived` is true when the ARN
    /// came from caller-controlled identity (subject_id / first-role /
    /// template substitution) rather than the operator's static
    /// `role_arn`. The caller (`issue_inner`) gates identity-derived
    /// ARNs on Verified trust.
    Role { arn: String, identity_derived: bool },
    /// Identity-derived value was empty AND no static fallback. Maps
    /// to NotAuthorized.
    EmptyDerived { reason: String },
    /// Template referenced a field that's None or out-of-bounds. Maps
    /// to NotAuthorized.
    SubstitutionFailed { field: String },
}

/// An IAM role ARN is well-formed only if it parses as
/// `arn:<partition>:iam::<account>:role/<name>`:
///
/// - exactly 6 colon-separated segments,
/// - segment 0 == `arn`, segment 2 == `iam`, segment 3 (region) empty
///   (IAM is global),
/// - partition is non-empty `[A-Za-z0-9-]`,
/// - account is exactly 12 ASCII digits,
/// - resource starts with `role/` and the remainder is a non-empty
///   IAM path/name (`[A-Za-z0-9+=,.@_/-]`).
///
/// The resolved ARN is handed straight to STS `AssumeRole`; rejecting
/// anything that isn't a role ARN stops a spoofed identity from
/// steering the call to an arbitrary / malformed principal. It is
/// stricter than AWS itself but rejects nothing a real IAM role ARN
/// would contain.
pub(crate) fn is_valid_role_arn(arn: &str) -> bool {
    if arn.len() > 2048 {
        return false;
    }
    let segs: Vec<&str> = arn.split(':').collect();
    if segs.len() != 6 {
        return false;
    }
    if segs[0] != "arn" || segs[2] != "iam" || !segs[3].is_empty() {
        return false;
    }
    let partition = segs[1];
    if partition.is_empty()
        || !partition
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return false;
    }
    let account = segs[4];
    if account.len() != 12 || !account.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Some(resource) = segs[5].strip_prefix("role/") else {
        return false;
    };
    !resource.is_empty()
        && resource.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'+' | b'=' | b',' | b'.' | b'@' | b'_' | b'/' | b'-')
        })
}

pub(crate) fn resolve_role(identity: &PluginIdentity, target: &TargetConfig) -> Resolution {
    match target.identity_mapping {
        IdentityMapping::Static => Resolution::Role {
            arn: target.role_arn.clone(),
            identity_derived: false,
        },
        IdentityMapping::SubjectId => match identity.subject_id.as_deref() {
            Some(s) if !s.is_empty() => Resolution::Role {
                arn: s.to_owned(),
                identity_derived: true,
            },
            _ if !target.role_arn.is_empty() => Resolution::Role {
                arn: target.role_arn.clone(),
                identity_derived: false,
            },
            _ => Resolution::EmptyDerived {
                reason: "identity has no subject_id and no static fallback role_arn".into(),
            },
        },
        IdentityMapping::FromRole => match identity.roles.first() {
            Some(r) if !r.is_empty() => Resolution::Role {
                arn: r.clone(),
                identity_derived: true,
            },
            _ if !target.role_arn.is_empty() => Resolution::Role {
                arn: target.role_arn.clone(),
                identity_derived: false,
            },
            _ => Resolution::EmptyDerived {
                reason: "identity has no roles and no static fallback role_arn".into(),
            },
        },
        IdentityMapping::Template => {
            // Validation guarantees role_arn_template is Some + non-empty
            // for Template mode.
            let template = target.role_arn_template.as_deref().unwrap_or("");
            substitute(template, identity)
        }
    }
}

/// Derive a SigV4 `RoleSessionName` from the caller for CloudTrail
/// attribution. STS requires `[\w+=,.@-]{2,64}`; we sanitise the
/// subject (replacing disallowed bytes with `-`), prepend the
/// operator prefix, and clamp to the length window. The session name
/// is attribution metadata, not an authorization boundary — the
/// assumed role's trust + session policy define the actual grants.
pub(crate) fn session_name(subject: Option<&str>, prefix: Option<&str>) -> String {
    let raw = subject.filter(|s| !s.is_empty()).unwrap_or("anonymous");
    let sanitized: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '+' | '=' | ',' | '.' | '@' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let mut name = match prefix.filter(|p| !p.is_empty()) {
        Some(p) => {
            let p: String = p
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric()
                        || matches!(c, '_' | '+' | '=' | ',' | '.' | '@' | '-')
                    {
                        c
                    } else {
                        '-'
                    }
                })
                .collect();
            format!("{p}-{sanitized}")
        }
        None => sanitized,
    };
    // Truncate to the 64-char ceiling on a char boundary (all chars are
    // single-byte ASCII after sanitisation, so byte truncation is safe).
    if name.len() > 64 {
        name.truncate(64);
    }
    // STS requires at least 2 chars; pad a degenerate result.
    if name.len() < 2 {
        name = "mcpg-session".to_owned();
    }
    name
}

/// Substitute `${identity.<field>}` placeholders. Mirrors the
/// `vault-dynamic-db` template engine; see [`resolve_field`] for the
/// supported fields.
fn substitute(template: &str, identity: &PluginIdentity) -> Resolution {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut placeholder = String::new();
            let mut closed = false;
            for ch in chars.by_ref() {
                if ch == '}' {
                    closed = true;
                    break;
                }
                placeholder.push(ch);
            }
            if !closed {
                return Resolution::SubstitutionFailed {
                    field: format!("unterminated placeholder `${{{placeholder}`"),
                };
            }
            let field = placeholder
                .strip_prefix("identity.")
                .unwrap_or(placeholder.as_str());
            match resolve_field(field, identity) {
                Some(s) if !s.is_empty() => out.push_str(&s),
                _ => {
                    return Resolution::SubstitutionFailed {
                        field: field.to_owned(),
                    };
                }
            }
        } else {
            out.push(c);
        }
    }
    if out.is_empty() {
        Resolution::EmptyDerived {
            reason: "template substitution produced an empty role ARN".into(),
        }
    } else {
        Resolution::Role {
            arn: out,
            identity_derived: true,
        }
    }
}

fn resolve_field(field: &str, identity: &PluginIdentity) -> Option<String> {
    match field {
        "subject_id" => identity.subject_id.clone(),
        "kind" => Some(identity.kind.clone()),
        "trust_level" => Some(identity.trust_level.clone()),
        "auth_provider" => identity.auth_provider.clone(),
        f if f.starts_with("attributes.") => {
            let key = &f["attributes.".len()..];
            identity.attributes.get(key).cloned()
        }
        f if let Some(idx) = parse_indexed(f, "roles") => identity.roles.get(idx).cloned(),
        f if let Some(idx) = parse_indexed(f, "groups") => identity.groups.get(idx).cloned(),
        f if let Some(idx) = parse_indexed(f, "scopes") => identity.scopes.get(idx).cloned(),
        _ => None,
    }
}

/// Parse `<name>[<idx>]` → `Some(idx)` when name matches.
fn parse_indexed(field: &str, name: &str) -> Option<usize> {
    let prefix = format!("{name}[");
    let rest = field.strip_prefix(&prefix)?;
    let inner = rest.strip_suffix(']')?;
    inner.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const ARN_A: &str = "arn:aws:iam::123456789012:role/team-a";
    const ARN_B: &str = "arn:aws:iam::123456789012:role/team-b";

    fn ident(subject: Option<&str>) -> PluginIdentity {
        let mut attrs = BTreeMap::new();
        attrs.insert("team".into(), "team-a".into());
        PluginIdentity {
            kind: "verified".into(),
            trust_level: "verified".into(),
            subject_id: subject.map(|s| s.to_owned()),
            auth_provider: Some("okta".into()),
            issuer: Some("https://okta.example.com".into()),
            roles: vec![ARN_A.into(), ARN_B.into()],
            groups: vec!["sec".into()],
            scopes: vec![],
            attributes: attrs,
        }
    }

    fn target(mapping: IdentityMapping, role_arn: &str, template: Option<&str>) -> TargetConfig {
        TargetConfig {
            role_arn: role_arn.into(),
            identity_mapping: mapping,
            role_arn_template: template.map(|s| s.to_owned()),
            allowed_role_arns: None,
            session_name_prefix: None,
            external_id: None,
            session_policy: None,
            duration_seconds: None,
            max_cache_ttl_ms: 60_000,
        }
    }

    fn assert_role(r: &Resolution, want: &str, want_derived: bool) {
        match r {
            Resolution::Role {
                arn,
                identity_derived,
            } => {
                assert_eq!(arn, want, "arn");
                assert_eq!(*identity_derived, want_derived, "identity_derived");
            }
            other => panic!("expected Role, got {other:?}"),
        }
    }

    #[test]
    fn arn_validation_accepts_real_arns() {
        assert!(is_valid_role_arn(ARN_A));
        assert!(is_valid_role_arn(
            "arn:aws:iam::000000000000:role/path/to/Role_Name-1"
        ));
        assert!(is_valid_role_arn(
            "arn:aws-us-gov:iam::123456789012:role/gov"
        ));
    }

    #[test]
    fn arn_validation_rejects_garbage_and_injection() {
        assert!(!is_valid_role_arn(""));
        assert!(!is_valid_role_arn("not-an-arn"));
        // wrong service
        assert!(!is_valid_role_arn("arn:aws:s3::123456789012:role/x"));
        // non-empty region segment
        assert!(!is_valid_role_arn(
            "arn:aws:iam:us-east-1:123456789012:role/x"
        ));
        // account not 12 digits
        assert!(!is_valid_role_arn("arn:aws:iam::123:role/x"));
        // not a role resource
        assert!(!is_valid_role_arn("arn:aws:iam::123456789012:user/x"));
        // missing role name
        assert!(!is_valid_role_arn("arn:aws:iam::123456789012:role/"));
        // a space sneaks in
        assert!(!is_valid_role_arn("arn:aws:iam::123456789012:role/a b"));
    }

    #[test]
    fn static_returns_configured_arn_not_derived() {
        let r = resolve_role(
            &ident(Some("x")),
            &target(IdentityMapping::Static, ARN_A, None),
        );
        assert_role(&r, ARN_A, false);
    }

    #[test]
    fn subject_id_returns_caller_subject_derived() {
        let r = resolve_role(
            &ident(Some(ARN_B)),
            &target(IdentityMapping::SubjectId, ARN_A, None),
        );
        assert_role(&r, ARN_B, true);
    }

    #[test]
    fn subject_id_falls_back_when_anonymous_not_derived() {
        let r = resolve_role(
            &ident(None),
            &target(IdentityMapping::SubjectId, ARN_A, None),
        );
        assert_role(&r, ARN_A, false);
    }

    #[test]
    fn subject_id_empty_derived_without_fallback() {
        let r = resolve_role(&ident(None), &target(IdentityMapping::SubjectId, "", None));
        assert!(matches!(r, Resolution::EmptyDerived { .. }));
    }

    #[test]
    fn from_role_returns_first_role_derived() {
        let r = resolve_role(
            &ident(Some("x")),
            &target(IdentityMapping::FromRole, ARN_A, None),
        );
        assert_role(&r, ARN_A, true);
    }

    #[test]
    fn template_substitutes_attribute_derived() {
        let r = resolve_role(
            &ident(Some("x")),
            &target(
                IdentityMapping::Template,
                "",
                Some("arn:aws:iam::123456789012:role/${identity.attributes.team}"),
            ),
        );
        assert_role(&r, ARN_A, true);
    }

    #[test]
    fn template_substitution_failure_surfaces_field() {
        let r = resolve_role(
            &ident(None),
            &target(
                IdentityMapping::Template,
                "",
                Some("arn:aws:iam::123456789012:role/${identity.subject_id}"),
            ),
        );
        match r {
            Resolution::SubstitutionFailed { field } => assert_eq!(field, "subject_id"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn session_name_sanitises_and_prefixes() {
        // disallowed chars (`:` `/`) become `-`.
        let n = session_name(Some("arn:aws:iam::1:role/x"), Some("mcpg"));
        assert!(n.starts_with("mcpg-"));
        assert!(
            n.chars().all(|c| c.is_ascii_alphanumeric()
                || matches!(c, '_' | '+' | '=' | ',' | '.' | '@' | '-'))
        );
    }

    #[test]
    fn session_name_handles_anonymous_and_length() {
        let n = session_name(None, None);
        assert_eq!(n, "anonymous");
        let long = "u".repeat(200);
        let n = session_name(Some(&long), Some("p"));
        assert!(n.len() <= 64);
        assert!(n.len() >= 2);
    }

    #[test]
    fn session_name_degenerate_falls_back() {
        // A single-char subject with no prefix would be < 2 chars.
        let n = session_name(Some("a"), None);
        assert_eq!(n, "mcpg-session");
    }
}
