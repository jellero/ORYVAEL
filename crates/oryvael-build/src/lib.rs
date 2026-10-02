#![forbid(unsafe_code)]

use oryvael_protocol::ChangePlan;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use thiserror::Error;

const MANIFEST_VERSION: &str = "oryvael-build-manifest/2";
const SBOM_FORMAT: &str = "oryvael-sbom/2";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    pub repository: String,
    pub commit: String,
    #[serde(default)]
    pub tree: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ToolchainIdentity {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactInput {
    pub name: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildManifestInput {
    pub change_id: String,
    pub builder_principal: String,
    pub source: SourceIdentity,
    pub toolchain: ToolchainIdentity,
    pub target: String,
    pub profile: String,
    pub build_command: Vec<String>,
    pub cargo_lock: PathBuf,
    pub cargo_metadata: PathBuf,
    pub artifacts: Vec<ArtifactInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactDigest {
    pub name: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct DependencyComponent {
    pub id: String,
    pub name: String,
    pub version: String,
    pub source: String,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub checksum: Option<String>,
    pub workspace: bool,
    #[serde(default)]
    pub dependencies: Vec<String>,
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
    pub normalized_input_sha256: String,
    pub cargo_lock_sha256: String,
    pub builder_principal: String,
    pub source: SourceIdentity,
    pub toolchain: ToolchainIdentity,
    pub target: String,
    pub profile: String,
    pub build_command: Vec<String>,
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

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<MetadataPackage>,
    #[serde(default)]
    workspace_members: Vec<String>,
    #[serde(default)]
    resolve: Option<MetadataResolve>,
}

#[derive(Debug, Deserialize)]
struct MetadataPackage {
    id: String,
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    checksum: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MetadataResolve {
    #[serde(default)]
    nodes: Vec<MetadataNode>,
}

#[derive(Debug, Deserialize)]
struct MetadataNode {
    id: String,
    #[serde(default)]
    deps: Vec<MetadataDep>,
}

#[derive(Debug, Deserialize)]
struct MetadataDep {
    pkg: String,
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
    let input: BuildManifestInput = serde_json::from_slice(&fs::read(input_path)?)?;
    let plan: ChangePlan = serde_json::from_slice(&plan_bytes)?;

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

    let cargo_lock_sha256 = sha256_file(&input.cargo_lock)?;

    let metadata: CargoMetadata =
        serde_json::from_slice(&fs::read(&input.cargo_metadata)?)?;
    let components = normalize_components(metadata)?;
    let sbom_payload = serde_json::to_vec(&(SBOM_FORMAT, &components))?;
    let sbom = Sbom {
        format: SBOM_FORMAT.into(),
        components,
        sha256: sha256_bytes(&sbom_payload),
    };

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

    let change_plan_sha256 = sha256_bytes(&plan_bytes);

    let normalized_input = (
        &input.change_id,
        &input.builder_principal,
        &input.source,
        &input.toolchain,
        &input.target,
        &input.profile,
        &input.build_command,
        &cargo_lock_sha256,
        &sbom.sha256,
        &artifacts,
    );
    let normalized_input_sha256 = sha256_bytes(&serde_json::to_vec(&normalized_input)?);

    let body = (
        MANIFEST_VERSION,
        &input.change_id,
        &change_plan_sha256,
        &normalized_input_sha256,
        &cargo_lock_sha256,
        &input.builder_principal,
        &input.source,
        &input.toolchain,
        &input.target,
        &input.profile,
        &input.build_command,
        &artifacts,
        &sbom,
    );
    let manifest_sha256 = sha256_bytes(&serde_json::to_vec(&body)?);

    Ok(BuildManifest {
        version: MANIFEST_VERSION.into(),
        change_id: input.change_id,
        change_plan_sha256,
        normalized_input_sha256,
        cargo_lock_sha256,
        builder_principal: input.builder_principal,
        source: input.source,
        toolchain: input.toolchain,
        target: input.target,
        profile: input.profile,
        build_command: input.build_command,
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
    if left.build_command != right.build_command {
        reasons.push("build command differs".into());
    }
    if left.cargo_lock_sha256 != right.cargo_lock_sha256 {
        reasons.push("Cargo.lock hash differs".into());
    }

    let independent_builders = left.builder_principal != right.builder_principal;
    if !independent_builders {
        reasons.push("builds are not independently attributed".into());
    }

    let sbom_match =
        left.sbom.sha256 == right.sbom.sha256 && left.sbom.components == right.sbom.components;
    if !sbom_match {
        reasons.push("SBOM differs".into());
    }

    let artifact_hashes_match =
        artifact_identity(&left.artifacts) == artifact_identity(&right.artifacts);
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

    if input.build_command.is_empty()
        || input.build_command.iter().any(|part| part.trim().is_empty())
    {
        return Err(BuildManifestError::InvalidInput(
            "build_command must contain non-empty arguments".into(),
        ));
    }

    for (label, path) in [
        ("cargo_lock", input.cargo_lock.as_path()),
        ("cargo_metadata", input.cargo_metadata.as_path()),
    ] {
        if !path.is_file() {
            return Err(BuildManifestError::InvalidInput(format!(
                "{label} is not a file: {}",
                path.display()
            )));
        }
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

    Ok(())
}

fn normalize_components(
    metadata: CargoMetadata,
) -> Result<Vec<DependencyComponent>, BuildManifestError> {
    let workspace_members = metadata
        .workspace_members
        .into_iter()
        .collect::<BTreeSet<_>>();

    let mut stable_ids = BTreeMap::new();
    let mut packages = BTreeMap::new();

    for package in metadata.packages {
        let workspace = workspace_members.contains(&package.id);
        let stable_id = stable_component_id(
            &package.name,
            &package.version,
            package.source.as_deref(),
            workspace,
        );

        if stable_ids
            .insert(package.id.clone(), stable_id)
            .is_some()
        {
            return Err(BuildManifestError::InvalidInput(format!(
                "duplicate cargo metadata package id: {}",
                package.id
            )));
        }
        packages.insert(package.id.clone(), (package, workspace));
    }

    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    if let Some(resolve) = metadata.resolve {
        for node in resolve.nodes {
            let owner = stable_ids.get(&node.id).cloned().ok_or_else(|| {
                BuildManifestError::InvalidInput(format!(
                    "resolve node references unknown package: {}",
                    node.id
                ))
            })?;

            let dependencies = edges.entry(owner).or_default();
            for dependency in node.deps {
                let stable = stable_ids.get(&dependency.pkg).ok_or_else(|| {
                    BuildManifestError::InvalidInput(format!(
                        "dependency references unknown package: {}",
                        dependency.pkg
                    ))
                })?;
                dependencies.insert(stable.clone());
            }
        }
    }

    let mut components = Vec::with_capacity(packages.len());
    for (metadata_id, (package, workspace)) in packages {
        let id = stable_ids
            .get(&metadata_id)
            .expect("stable id exists for every metadata package")
            .clone();
        let source = if workspace {
            "workspace".to_owned()
        } else {
            package.source.unwrap_or_else(|| "unknown".into())
        };

        components.push(DependencyComponent {
            dependencies: edges.remove(&id).unwrap_or_default().into_iter().collect(),
            id,
            name: package.name,
            version: package.version,
            source,
            license: package.license,
            checksum: package.checksum,
            workspace,
        });
    }

    components.sort();
    Ok(components)
}

fn stable_component_id(
    name: &str,
    version: &str,
    source: Option<&str>,
    workspace: bool,
) -> String {
    if workspace {
        format!("workspace:{name}@{version}")
    } else {
        format!("cargo:{name}@{version}#{}", source.unwrap_or("unknown"))
    }
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
    fn workspace_component_id_ignores_host_path() {
        assert_eq!(
            stable_component_id(
                "oryvael-build",
                "0.1.0",
                Some("path+file:///different/host/path"),
                true
            ),
            "workspace:oryvael-build@0.1.0"
        );
    }

    #[test]
    fn external_component_id_binds_resolved_source() {
        assert_eq!(
            stable_component_id(
                "serde",
                "1.0.229",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                false
            ),
            "cargo:serde@1.0.229#registry+https://github.com/rust-lang/crates.io-index"
        );
    }

    #[test]
    fn reproducibility_requires_independent_matching_builds() {
        let base = BuildManifest {
            version: MANIFEST_VERSION.into(),
            change_id: "CHG-1".into(),
            change_plan_sha256: "a".repeat(64),
            normalized_input_sha256: "b".repeat(64),
            cargo_lock_sha256: "c".repeat(64),
            builder_principal: "build/one".into(),
            source: SourceIdentity {
                repository: "repo".into(),
                commit: "commit".into(),
                tree: None,
            },
            toolchain: ToolchainIdentity {
                name: "rust".into(),
                version: "1.85.0".into(),
                sha256: None,
            },
            target: "x86_64-unknown-linux-gnu".into(),
            profile: "release".into(),
            build_command: vec!["cargo".into(), "build".into(), "--locked".into()],
            artifacts: vec![ArtifactDigest {
                name: "image".into(),
                sha256: "d".repeat(64),
                bytes: 1,
            }],
            sbom: Sbom {
                format: SBOM_FORMAT.into(),
                components: vec![],
                sha256: "e".repeat(64),
            },
            manifest_sha256: "f".repeat(64),
        };

        let mut independent = base.clone();
        independent.builder_principal = "build/two".into();
        independent.normalized_input_sha256 = "1".repeat(64);
        independent.manifest_sha256 = "2".repeat(64);
        assert!(compare(&base, &independent).reproducible);

        let mut changed = independent;
        changed.artifacts[0].sha256 = "0".repeat(64);
        let report = compare(&base, &changed);
        assert!(!report.reproducible);
        assert!(!report.artifact_hashes_match);
    }

    #[test]
    fn sha256_validation_is_strict() {
        assert!(require_sha256("x", &"a".repeat(64)).is_ok());
        assert!(require_sha256("x", &"g".repeat(64)).is_err());
        assert!(require_sha256("x", &"a".repeat(63)).is_err());
    }
}
