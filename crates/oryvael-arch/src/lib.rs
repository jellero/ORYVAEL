#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    Kernel,
    TrustedCore,
    SystemService,
    AiControl,
    Application,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Component {
    pub id: String,
    pub layer: Layer,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub allowed_dependencies: Vec<String>,
    #[serde(default)]
    pub forbidden_dependencies: Vec<String>,
    #[serde(default)]
    pub capabilities_required: Vec<String>,
    #[serde(default)]
    pub capabilities_exposed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Architecture {
    pub version: String,
    pub components: Vec<Component>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Violation {
    pub code: String,
    pub component: String,
    pub message: String,
}

pub fn validate(architecture: &Architecture) -> Vec<Violation> {
    let mut violations = Vec::new();
    let mut seen = HashSet::new();
    let by_id: HashMap<&str, &Component> = architecture
        .components
        .iter()
        .map(|component| (component.id.as_str(), component))
        .collect();

    for component in &architecture.components {
        if !seen.insert(component.id.as_str()) {
            violations.push(Violation {
                code: "ARCH_DUPLICATE_COMPONENT".into(),
                component: component.id.clone(),
                message: "component id appears more than once".into(),
            });
        }

        for dependency in &component.dependencies {
            let Some(target) = by_id.get(dependency.as_str()) else {
                violations.push(Violation {
                    code: "ARCH_UNKNOWN_DEPENDENCY".into(),
                    component: component.id.clone(),
                    message: format!("unknown dependency: {dependency}"),
                });
                continue;
            };

            if component.forbidden_dependencies.contains(dependency) {
                violations.push(Violation {
                    code: "ARCH_FORBIDDEN_DEPENDENCY".into(),
                    component: component.id.clone(),
                    message: format!("forbidden dependency: {dependency}"),
                });
            }

            if !component.allowed_dependencies.is_empty()
                && !component.allowed_dependencies.contains(dependency)
            {
                violations.push(Violation {
                    code: "ARCH_NOT_ALLOWLISTED".into(),
                    component: component.id.clone(),
                    message: format!("dependency is not allowlisted: {dependency}"),
                });
            }

            if !layer_dependency_allowed(&component.layer, &target.layer) {
                violations.push(Violation {
                    code: "ARCH_LAYER_VIOLATION".into(),
                    component: component.id.clone(),
                    message: format!(
                        "layer {:?} may not depend on {:?} component {}",
                        component.layer, target.layer, dependency
                    ),
                });
            }
        }
    }

    violations
}

fn layer_dependency_allowed(source: &Layer, target: &Layer) -> bool {
    matches!(
        (source, target),
        (Layer::Kernel, Layer::Kernel)
            | (Layer::TrustedCore, Layer::Kernel | Layer::TrustedCore)
            | (
                Layer::SystemService,
                Layer::Kernel | Layer::TrustedCore | Layer::SystemService
            )
            | (
                Layer::AiControl,
                Layer::TrustedCore | Layer::SystemService | Layer::AiControl
            )
            | (
                Layer::Application,
                Layer::SystemService | Layer::Application
            )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn component(id: &str, layer: Layer, dependencies: &[&str]) -> Component {
        Component {
            id: id.into(),
            layer,
            dependencies: dependencies.iter().map(|v| (*v).into()).collect(),
            allowed_dependencies: vec![],
            forbidden_dependencies: vec![],
            capabilities_required: vec![],
            capabilities_exposed: vec![],
        }
    }

    #[test]
    fn trusted_core_cannot_depend_on_ai_control() {
        let architecture = Architecture {
            version: "1".into(),
            components: vec![
                component("policy", Layer::TrustedCore, &["developer-ai"]),
                component("developer-ai", Layer::AiControl, &[]),
            ],
        };

        let violations = validate(&architecture);
        assert!(violations.iter().any(|v| v.code == "ARCH_LAYER_VIOLATION"));
    }

    #[test]
    fn application_can_depend_on_system_service() {
        let architecture = Architecture {
            version: "1".into(),
            components: vec![
                component("app", Layer::Application, &["fs-broker"]),
                component("fs-broker", Layer::SystemService, &[]),
            ],
        };

        assert!(validate(&architecture).is_empty());
    }
}
