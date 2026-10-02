#![forbid(unsafe_code)]

use oryvael_protocol::{CapabilityGrant, Effect, Operation, Principal};
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub matched_grant: Option<usize>,
    pub reason: String,
}

pub fn evaluate(principal: &Principal, operation: &Operation) -> PolicyDecision {
    for (index, grant) in principal.grants.iter().enumerate() {
        if grant.effect == Effect::Deny && grant_matches(grant, operation) {
            return PolicyDecision {
                allowed: false,
                matched_grant: Some(index),
                reason: "explicit deny matched".into(),
            };
        }
    }

    for (index, grant) in principal.grants.iter().enumerate() {
        if grant.effect == Effect::Allow && grant_matches(grant, operation) {
            return PolicyDecision {
                allowed: true,
                matched_grant: Some(index),
                reason: "explicit allow matched".into(),
            };
        }
    }

    PolicyDecision {
        allowed: false,
        matched_grant: None,
        reason: "default deny: no matching allow".into(),
    }
}

fn grant_matches(grant: &CapabilityGrant, operation: &Operation) -> bool {
    let resource_matches = grant.resource == "*" || grant.resource == operation.resource;
    let action_matches = grant
        .actions
        .iter()
        .any(|action| action == "*" || action == &operation.action);

    resource_matches && action_matches && scope_matches(grant.scope.as_deref(), operation.target.as_deref())
}

fn scope_matches(scope: Option<&str>, target: Option<&str>) -> bool {
    let Some(scope) = scope else {
        return true;
    };
    let Some(target) = target else {
        return false;
    };

    scope.split(',').map(str::trim).any(|candidate| {
        if candidate == "*" || candidate == "/**" {
            return true;
        }

        if let Some(prefix) = candidate.strip_suffix("/**") {
            return target == prefix || target.starts_with(&format!("{prefix}/"));
        }

        candidate == target
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use oryvael_protocol::{CapabilityGrant, PrincipalKind};

    fn principal(grants: Vec<CapabilityGrant>) -> Principal {
        Principal {
            principal: "developer-ai/test".into(),
            kind: PrincipalKind::AiAgent,
            grants,
        }
    }

    fn grant(effect: Effect, resource: &str, actions: &[&str], scope: Option<&str>) -> CapabilityGrant {
        CapabilityGrant {
            effect,
            resource: resource.into(),
            actions: actions.iter().map(|v| (*v).into()).collect(),
            scope: scope.map(str::to_owned),
            expires_at: None,
            delegable: false,
        }
    }

    #[test]
    fn default_is_deny() {
        let decision = evaluate(
            &principal(vec![]),
            &Operation { resource: "source".into(), action: "read".into(), target: None },
        );
        assert!(!decision.allowed);
    }

    #[test]
    fn explicit_deny_overrides_allow() {
        let p = principal(vec![
            grant(Effect::Allow, "source", &["write"], Some("/workspace/**")),
            grant(Effect::Deny, "source", &["write"], Some("/workspace/protected/**")),
        ]);
        let decision = evaluate(
            &p,
            &Operation {
                resource: "source".into(),
                action: "write".into(),
                target: Some("/workspace/protected/key".into()),
            },
        );
        assert!(!decision.allowed);
        assert_eq!(decision.matched_grant, Some(1));
    }

    #[test]
    fn prefix_scope_allows_only_inside_prefix() {
        let p = principal(vec![grant(
            Effect::Allow,
            "source",
            &["write"],
            Some("/workspace/change-1/**"),
        )]);

        assert!(evaluate(
            &p,
            &Operation {
                resource: "source".into(),
                action: "write".into(),
                target: Some("/workspace/change-1/file.rs".into()),
            },
        ).allowed);

        assert!(!evaluate(
            &p,
            &Operation {
                resource: "source".into(),
                action: "write".into(),
                target: Some("/etc/passwd".into()),
            },
        ).allowed);
    }
}
