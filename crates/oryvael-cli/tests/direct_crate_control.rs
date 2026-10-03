#![forbid(unsafe_code)]

use std::fmt::Display;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn unsigned_copy(source: &Path, label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let target = std::env::temp_dir().join(format!(
        "oryvael-direct-api-{label}-{}-{stamp}.json",
        std::process::id()
    ));
    fs::copy(source, &target).expect("copy unsigned control fixture");
    target
}

fn assert_control_rejected<T, E: Display>(label: &str, result: Result<T, E>) {
    let error = match result {
        Ok(_) => panic!("{label} accepted an unsigned privileged control artifact"),
        Err(error) => error,
    };
    let rendered = error.to_string();
    assert!(
        rendered.contains("control verification failed"),
        "{label} failed for the wrong reason: {rendered}"
    );
}

#[test]
fn direct_file_based_crate_apis_fail_closed() {
    let root = repo_root();

    let unsigned_supervisor_principal = unsigned_copy(
        &root.join("examples/supervisor/developer-principal.json"),
        "supervisor-principal",
    );
    assert_control_rejected(
        "supervisor",
        oryvael_supervisor::run_from_files(
            &unsigned_supervisor_principal,
            root.join("examples/supervisor/job.json"),
        ),
    );

    let unsigned_workspace_principal = unsigned_copy(
        &root.join("examples/workspace/developer-principal.json"),
        "workspace-principal",
    );
    assert_control_rejected(
        "workspace",
        oryvael_workspace::create_from_files(
            &unsigned_workspace_principal,
            root.join("examples/workspace/registry.json"),
            root.join("examples/workspace/request.json"),
        ),
    );

    let unsigned_tool_principal = unsigned_copy(
        &root.join("examples/tool-broker/developer-principal.json"),
        "tool-principal",
    );
    assert_control_rejected(
        "tool-broker",
        oryvael_tool_broker::run_brokered_from_files(
            &unsigned_tool_principal,
            root.join("examples/tool-broker/catalog.json"),
            root.join("examples/tool-broker/invocation.json"),
        ),
    );

    let unsigned_build_plan = unsigned_copy(
        &root.join("examples/build/c1-plan.json"),
        "build-plan",
    );
    assert_control_rejected(
        "build",
        oryvael_build::build_from_files(
            &unsigned_build_plan,
            root.join("examples/build/input.json"),
        ),
    );

    let unsigned_proof_plan = unsigned_copy(
        &root.join("examples/proof/c2-plan.json"),
        "proof-plan",
    );
    assert_control_rejected(
        "proof",
        oryvael_proof::build_from_files(
            &unsigned_proof_plan,
            root.join("examples/proof/c2-evidence.json"),
        ),
    );

    for path in [
        unsigned_supervisor_principal,
        unsigned_workspace_principal,
        unsigned_tool_principal,
        unsigned_build_plan,
        unsigned_proof_plan,
    ] {
        let _ = fs::remove_file(path);
    }
}
