use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn build_fixture(name: &str) -> PathBuf {
    let output_dir = repo_root().join("target").join("ptrace-fixtures");
    std::fs::create_dir_all(&output_dir).unwrap();

    let source = repo_root().join("tests").join("fixtures").join(format!("{name}.c"));
    let binary = output_dir.join(name);

    let status = Command::new("cc")
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .status()
        .unwrap();
    assert!(status.success(), "failed to compile fixture {name}");

    binary
}

fn run_syscage(binary: &Path, extra_args: &[&str]) -> String {
    let syscage = env!("CARGO_BIN_EXE_syscage");
    let mut command = Command::new(syscage);
    command.arg("check").arg(binary);
    if !extra_args.is_empty() {
        command.arg("--");
        command.args(extra_args);
    }

    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "syscage failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
#[ignore = "requires ptrace permissions outside restricted sandboxes"]
fn argv0_is_preserved_for_tracee() {
    let fixture = build_fixture("argv_probe");
    let output = run_syscage(&fixture, &["marker"]);

    assert!(output.contains("argc=2"));
    assert!(output.contains(&format!("argv[0]={}", fixture.display())));
    assert!(output.contains("argv[1]=marker"));
}

#[test]
#[ignore = "requires ptrace permissions outside restricted sandboxes"]
fn prctl_filter_is_detected() {
    let fixture = build_fixture("seccomp_prctl_allow");
    let output = run_syscage(&fixture, &[]);

    assert!(output.contains("prctl(PR_SET_SECCOMP)"));
    assert!(output.contains("return KILL_PROCESS"));
    assert!(output.contains("return ALLOW"));
}

#[test]
#[ignore = "requires ptrace permissions outside restricted sandboxes"]
fn seccomp_flags_are_reported() {
    let fixture = build_fixture("seccomp_tsync_allow");
    let output = run_syscage(&fixture, &[]);

    assert!(output.contains("flags=0x1 [TSYNC]"));
}

#[test]
#[ignore = "requires ptrace permissions outside restricted sandboxes"]
fn poisoned_padding_does_not_break_program_length_parsing() {
    let fixture = build_fixture("seccomp_padding_poison");
    let output = run_syscage(&fixture, &[]);

    assert!(output.contains("0000: 0x06 0x00 0x00 0x7fff0000  return ALLOW"));
    assert!(!output.contains("capacity overflow"));
}

#[test]
#[ignore = "requires ptrace permissions outside restricted sandboxes"]
fn jset_and_errno_are_decoded() {
    let fixture = build_fixture("seccomp_jset_errno");
    let output = run_syscage(&fixture, &[]);

    assert!(output.contains("if ((A & 0x40000000) == 0) goto 0003"));
    assert!(output.contains("return ERRNO(1)"));
}
