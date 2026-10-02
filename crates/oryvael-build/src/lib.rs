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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReproducibilityReport {
    pub reproducible: bool,
    pub independent_builders: bool,
    pub left_manifest_sha256: String,
    pub right_manifest_sha256: String,
    pub artifact_hashes_match: bool,
    pub sbom_match: bool,
    pub reasons: Vec<String>,
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

pub fn compare_from_files(
    left_path: impl AsRef<Path>,
    right_path: impl AsRef<Path>,
) -> Result<ReproducibilityReport, BuildManifestError> {
    let left: BuildManifest = serde_json::from_slice(&fs::read(left_path)?)?;
    let right: BuildManifest = serde_json::from_slice(&fs::read(right_path)?)?;
    Ok(compare(&left, &right))
}

pub fn compare(left: &BuildManifest, right: &BuildManifest) -> ReproducibilityReport {
    let mut reasons = Vec::new();

    if left.change_id != right.change_id {
        reasons.push("change id differs".into());
    }
    if left.change_plan_sha256 != right.change_plan_sha256 {
        reasons.push("change-plan hash differs".into());
    }
    if left.source != right.source {
        reasons.push("source identity differs".into());
    }
    if left.toolchain != right.toolchain {
        reasons.push("toolchain identity differs".into());
    }
    if left.target != right.target {
        reasons.push("target differs".into());
    }
    if left.profile != right.profile {
        reasons.push("build profile differs".into());
    }

    let independent_builders = left.builder_principal != right.builder_principal;
    if !independent_builders {
        reasons.push("builds are not independently attributed".into());
    }

    let sbom_match = left.sbom.sha256 == right.sbom.sha256
        && left.sbom.components == right.sbom.components;
    if !sbom_match {
        reasons.push("SBOM differs".into());
    }

    let artifact_hashes_match = artifact_identity(&left.artifacts)
        == artifact_identity(&right.artifacts);
    if !artifact_hashes_match {
        reasons.push("artifact hashes differ".into());
    }

    ReproducibilityReport {
        reproducible: reasons.is_empty(),
        independent_builders,
        left_manifest_sha256: left.manifest_sha256.clone(),
        right_manifest_sha256: right.manifest_sha256.clone(),
        artifact_hashes_match,
        sbom_match,
        reasons,
    }
}

fn artifact_identity(artifacts: &[ArtifactDigest]) -> Vec<(&str, &str, u64)> {
    let mut identity = artifacts
        .iter()
        .map(|artifact| {
            (
                artifact.name.as_str(),
                artifact.sha256.as_str(),
                artifact.bytes,
            )
        })
        .collect::<Vec<_>>();
    identity.sort_unstable();
    identity
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
    fn reproducibility_requires_independent_matching_builds() {
        let manifest = BuildManifest {
            version: MANIFEST_VERSION.into(),
            change_id: "CHG-1".into(),
            change_plan_sha256: "a".repeat(64),
            input_sha256: "b".repeat(64),
            builder_principal: "build/one".into(),
            source: SourceIdentity {
                repository: "repo".into(),
                commit: "commit".into(),
                tree: None,
            },
            toolchain: ToolchainIdentity {
                name: "rust".into(),
                version: "1".into(),
                sha256: None,
            },
            target: "target".into(),
            profile: "release".into(),
            artifacts: vec![ArtifactDigest {
                name: "image".into(),
                sha256: "c".repeat(64),
                bytes: 1,
            }],
            sbom: Sbom {
                format: SBOM_FORMAT.into(),
                components: vec![],
                sha256: "d".repeat(64),
            },
            manifest_sha256: "e".repeat(64),
        };

        let mut independent = manifest.clone();
        independent.builder_principal = "build/two".into();
        independent.manifest_sha256 = "f".repeat(64);
        assert!(compare(&manifest, &independent).reproducible);

        let mut changed = independent;
        changed.artifacts[0].sha256 = "0".repeat(64);
        assert!(!compare(&manifest, &changed).reproducible);
    }

    #[test]
    fn sha256_validation_is_strict() {
        assert!(require_sha256("x", &"a".repeat(64)).is_ok());
        assert!(require_sha256("x", &"g".repeat(64)).is_err());
        assert!(require_sha256("x", &"a".repeat(63)).is_err());
    }
}
