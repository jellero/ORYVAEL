#![forbid(unsafe_code)]

use oryvael_protocol::ChangePlan;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use thiserror::Error;

const MANIFEST_VERSION: &str = "oryvael-build-manifest/1";
const SBOM_FORMAT: &str = "oryvael-sbom/1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceIdentity {
    pub repository: String,
    pub commit: String,
    #[serde(default)]
    pub tree: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolchainIdentity {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactInput {
    pub name: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct DependencyComponent {
    pub name: String,
    pub version: String,
    pub source: String,
    #[serde(default)]
    pub checksum: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildManifestInput {
    pub change_id: String,
    pub builder_principal: String,
    pub source: SourceIdentity,
    pub toolchain: ToolchainIdentity,
    pub target: String,
    pub profile: String,
    pub artifacts: Vec<ArtifactInput>,
    #[serde(default)]
    pub dependencies: Vec<DependencyComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactDigest {
    pub name: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Sbom {
    pub format: String,
    pub components: Vec<DependencyComponent>,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildManifest {
    pub version: String,
    pub change_id: String,
    pub change_plan_sha256: String,
    pub input_sha256: String,
    pub builder_principal: String,
    pub source: SourceIdentity,
    pub toolchain: ToolchainIdentity,
    pub target: String,
    pub profile: String,
    pub artifacts: Vec<ArtifactDigest>,
    pub sbom: Sbom,
    pub manifest_sha256: String,
}

#[derive(Debug, Error)]
pub enum BuildManifestError {
    #[error("change id mismatch: plan is {plan}, input is {input}")]
    ChangeIdMismatch { plan: String, input: String },
    #[error("change plan does not authorize build:manifest")]
    BuildNotAuthorized,
    #[error("invalid build manifest input: {0}")]
    InvalidInput(String),
    #[error("artifact does not exist or is not a file: {0}")]
    InvalidArtifact(PathBuf),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn build_from_files(
    plan_path: impl AsRef<Path>,
    input_path: impl AsRef<Path>,
) -> Result<BuildManifest, BuildManifestError> {
    let plan_bytes = fs::read(plan_path)?;
    let input_bytes = fs::read(input_path)?;
    let plan: ChangePlan = serde_json::from_slice(&plan_bytes)?;
    let input: BuildManifestInput = serde_json::from_slice(&input_bytes)?;

    if plan.id != input.change_id {
        return Err(BuildManifestError::ChangeIdMismatch {
            plan: plan.id,
            input: input.change_id,
        });
    }

    if !plan
        .requested_capabilities
        .iter()
        .any(|capability| capability == "build:manifest")
    {
        return Err(BuildManifestError::BuildNotAuthorized);
    }

    validate_input(&input)?;

    let mut artifacts = Vec::with_capacity(input.artifacts.len());
    for artifact in &input.artifacts {
        let metadata = fs::metadata(&artifact.path)?;
        if !metadata.is_file() {
            return Err(BuildManifestError::InvalidArtifact(artifact.path.clone()));
        }
        artifacts.push(ArtifactDigest {
            name: artifact.name.clone(),
            sha256: sha256_file(&artifact.path)?,
            bytes: metadata.len(),
        });
    }
    artifacts.sort_by(|left, right| left.name.cmp(&right.name));

    let mut components = input.dependencies.clone();
    components.sort();
    components.dedup();

    let sbom_payload = serde_json::to_vec(&(SBOM_FORMAT, &components))?;
    let sbom = Sbom {
        format: SBOM_FORMAT.into(),
        components,
        sha256: sha256_bytes(&sbom_payload),
    };

    let change_plan_sha256 = sha256_bytes(&plan_bytes);
    let input_sha256 = sha256_bytes(&input_bytes);

    let body = (
        MANIFEST_VERSION,
        &input.change_id,
        &change_plan_sha256,
        &input_sha256,
        &input.builder_principal,
        &input.source,
        &input.toolchain,
        &input.target,
        &input.profile,
        &artifacts,
        &sbom,
    );
    let manifest_sha256 = sha256_bytes(&serde_json::to_vec(&body)?);

    Ok(BuildManifest {
        version: MANIFEST_VERSION.into(),
        change_id: input.change_id,
        change_plan_sha256,
        input_sha256,
        builder_principal: input.builder_principal,
        source: input.source,
        toolchain: input.toolchain,
        target: input.target,
        profile: input.profile,
        artifacts,
        sbom,
        manifest_sha256,
    })
}

fn validate_input(input: &BuildManifestInput) -> Result<(), BuildManifestError> {
    for (label, value) in [
        ("change_id", input.change_id.as_str()),
        ("builder_principal", input.builder_principal.as_str()),
        ("source.repository", input.source.repository.as_str()),
        ("source.commit", input.source.commit.as_str()),
        ("toolchain.name", input.toolchain.name.as_str()),
        ("toolchain.version", input.toolchain.version.as_str()),
        ("target", input.target.as_str()),
        ("profile", input.profile.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(BuildManifestError::InvalidInput(format!(
                "{label} must not be empty"
            )));
        }
    }

    if let Some(hash) = &input.toolchain.sha256 {
        require_sha256("toolchain.sha256", hash)?;
    }

    if input.artifacts.is_empty() {
        return Err(BuildManifestError::InvalidInput(
            "at least one artifact is required".into(),
        ));
    }

    let mut artifact_names = BTreeSet::new();
    for artifact in &input.artifacts {
        if artifact.name.trim().is_empty() {
            return Err(BuildManifestError::InvalidInput(
                "artifact name must not be empty".into(),
            ));
        }
        if !artifact_names.insert(artifact.name.as_str()) {
            return Err(BuildManifestError::InvalidInput(format!(
                "duplicate artifact name: {}",
                artifact.name
            )));
        }
    }

    let mut dependencies = BTreeSet::new();
    for component in &input.dependencies {
        if component.name.trim().is_empty()
            || component.version.trim().is_empty()
            || component.source.trim().is_empty()
        {
            return Err(BuildManifestError::InvalidInput(
                "dependency name, version and source must not be empty".into(),
            ));
        }
        if let Some(checksum) = &component.checksum {
            require_sha256("dependency checksum", checksum)?;
        }
        if !dependencies.insert((
            component.name.as_str(),
            component.version.as_str(),
            component.source.as_str(),
        )) {
            return Err(BuildManifestError::InvalidInput(format!(
                "duplicate dependency identity: {} {} {}",
                component.name, component.version, component.source
            )));
        }
    }

    Ok(())
}

fn require_sha256(label: &str, value: &str) -> Result<(), BuildManifestError> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(BuildManifestError::InvalidInput(format!(
            "{label} is not a SHA-256 value"
        )))
    }
}

fn sha256_file(path: &Path) -> Result<String, std::io::Error> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];

    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependency_order_is_canonical() {
        let mut items = [
            DependencyComponent {
                name: "z".into(),
                version: "1".into(),
                source: "registry".into(),
                checksum: None,
            },
            DependencyComponent {
                name: "a".into(),
                version: "1".into(),
                source: "registry".into(),
                checksum: None,
            },
        ];
        items.sort();
        assert_eq!(items[0].name, "a");
    }

    #[test]
    fn sha256_validation_is_strict() {
        assert!(require_sha256("x", &"a".repeat(64)).is_ok());
        assert!(require_sha256("x", &"g".repeat(64)).is_err());
        assert!(require_sha256("x", &"a".repeat(63)).is_err());
    }
}
