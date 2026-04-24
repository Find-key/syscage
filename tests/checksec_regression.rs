use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn build_fixture(name: &str, flags: &[&str]) -> PathBuf {
    let output_dir = repo_root().join("target").join("checksec-fixtures");
    std::fs::create_dir_all(&output_dir).unwrap();

    let source = repo_root().join("tests").join("fixtures").join("checksec_probe.c");
    let binary = output_dir.join(name);

    let mut command = Command::new("cc");
    command.arg(&source).arg("-o").arg(&binary);
    command.args(flags);

    let status = command.status().unwrap();
    assert!(status.success(), "failed to compile fixture {name}");

    binary
}

fn build_source_fixture(name: &str, source_code: &str, flags: &[&str]) -> PathBuf {
    let output_dir = repo_root().join("target").join("checksec-fixtures");
    std::fs::create_dir_all(&output_dir).unwrap();

    let source = output_dir.join(format!("{name}.c"));
    let binary = output_dir.join(name);
    std::fs::write(&source, source_code).unwrap();

    let mut command = Command::new("cc");
    command.arg(&source).arg("-o").arg(&binary);
    command.args(flags);

    let status = command.status().unwrap();
    assert!(status.success(), "failed to compile fixture {name}");

    binary
}

fn run_checksec(binary: &Path) -> String {
    let syscage = env!("CARGO_BIN_EXE_syscage");
    let output = Command::new(syscage)
        .arg("checksec")
        .arg(binary)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "checksec failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn run_checksec_failure(path: &Path) -> String {
    let syscage = env!("CARGO_BIN_EXE_syscage");
    let output = Command::new(syscage)
        .arg("checksec")
        .arg(path)
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "checksec unexpectedly succeeded on {}",
        path.display()
    );

    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn write_fixture_file(name: &str, data: &[u8]) -> PathBuf {
    let output_dir = repo_root().join("target").join("checksec-fixtures");
    std::fs::create_dir_all(&output_dir).unwrap();

    let path = output_dir.join(name);
    std::fs::write(&path, data).unwrap();
    path
}

fn write_minimal_elf(
    name: &str,
    class: u8,
    data_encoding: u8,
    machine: u16,
    elf_type: u16,
) -> PathBuf {
    let header_size = if class == 1 { 0x34 } else { 0x40 };
    let mut data = vec![0u8; header_size];
    data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    data[4] = class;
    data[5] = data_encoding;
    data[6] = 1;

    let write_u16 = |buf: &mut [u8], offset: usize, value: u16| {
        let encoded = if data_encoding == 2 {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        buf[offset..offset + 2].copy_from_slice(&encoded);
    };
    let write_u32 = |buf: &mut [u8], offset: usize, value: u32| {
        let encoded = if data_encoding == 2 {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        buf[offset..offset + 4].copy_from_slice(&encoded);
    };

    write_u16(&mut data, 0x10, elf_type);
    write_u16(&mut data, 0x12, machine);
    write_u32(&mut data, 0x14, 1);

    let ehsize_offset = if class == 1 { 0x28 } else { 0x34 };
    write_u16(&mut data, ehsize_offset, header_size as u16);

    write_fixture_file(name, &data)
}

fn parse_report(output: &str) -> HashMap<String, String> {
    strip_ansi(output)
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
        .collect()
}

fn checksec_report(path: &Path) -> HashMap<String, String> {
    parse_report(&run_checksec(path))
}

fn strip_ansi(text: &str) -> String {
    let mut result = String::new();
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && matches!(chars.peek(), Some('[')) {
            chars.next();
            for next in chars.by_ref() {
                if next == 'm' {
                    break;
                }
            }
            continue;
        }
        result.push(ch);
    }

    result
}

fn assert_has_color(output: &str, color: &str, text: &str) {
    assert!(
        output.contains(&format!("{color}{text}\u{1b}[0m")),
        "missing colorized value {text} in output:\n{output}"
    );
}

#[test]
fn hardened_binary_reports_expected_protections() {
    let binary = build_fixture(
        "hardened",
        &[
            "-O2",
            "-D_FORTIFY_SOURCE=2",
            "-fstack-protector-all",
            "-fPIE",
            "-pie",
            "-Wl,-z,relro,-z,now",
        ],
    );
    let output = run_checksec(&binary);
    let report = parse_report(&output);

    assert_eq!(report.get("Arch").unwrap(), "amd64-64-little");
    assert_eq!(report.get("RELRO").unwrap(), "Full RELRO");
    assert!(report.contains_key("SHSTK"));
    assert!(report.contains_key("IBT"));
    assert_eq!(report.get("Canary").unwrap(), "Enabled");
    assert_eq!(report.get("NX").unwrap(), "Enabled");
    assert_eq!(report.get("PIE").unwrap(), "Enabled");
    assert_eq!(report.get("FORTIFY").unwrap(), "Enabled");
    assert_has_color(&output, "\u{1b}[32m", "Full RELRO");
    assert_has_color(&output, "\u{1b}[32m", "Enabled");
}

#[test]
fn static_hardened_binary_reports_local_canary_and_fortify() {
    let binary = build_fixture(
        "static-hardened",
        &[
            "-O2",
            "-D_FORTIFY_SOURCE=2",
            "-fstack-protector-all",
            "-static",
            "-no-pie",
            "-Wl,-z,relro,-z,now",
        ],
    );
    let report = checksec_report(&binary);

    assert_eq!(report.get("Canary").unwrap(), "Enabled");
    assert_eq!(report.get("FORTIFY").unwrap(), "Enabled");
    assert_eq!(report.get("NX").unwrap(), "Enabled");
    assert!(report.get("PIE").unwrap().starts_with("Disabled (base 0x"));
}

#[test]
fn partial_relro_binary_is_yellow() {
    let binary = build_fixture(
        "partial-relro",
        &[
            "-O2",
            "-fstack-protector-all",
            "-fPIE",
            "-pie",
            "-Wl,-z,relro,-z,lazy",
        ],
    );
    let output = run_checksec(&binary);
    let report = parse_report(&output);

    assert_eq!(report.get("RELRO").unwrap(), "Partial RELRO");
    assert_has_color(&output, "\u{1b}[33m", "Partial RELRO");
}

#[test]
fn relaxed_binary_reports_disabled_protections_and_base() {
    let binary = build_fixture(
        "relaxed",
        &[
            "-O0",
            "-fno-stack-protector",
            "-no-pie",
            "-U_FORTIFY_SOURCE",
            "-Wl,-z,norelro",
            "-Wl,-z,execstack",
        ],
    );
    let output = run_checksec(&binary);
    let report = parse_report(&output);

    assert_eq!(report.get("RELRO").unwrap(), "No RELRO");
    assert!(report.contains_key("SHSTK"));
    assert!(report.contains_key("IBT"));
    assert_eq!(report.get("Canary").unwrap(), "Disabled");
    assert_eq!(report.get("NX").unwrap(), "Disabled");
    assert!(report.get("PIE").unwrap().starts_with("Disabled (base 0x"));
    assert_eq!(report.get("FORTIFY").unwrap(), "Disabled");
    assert_has_color(&output, "\u{1b}[31m", "No RELRO");
}

#[test]
fn rpath_and_runpath_are_reported_independently() {
    let rpath_binary = build_fixture(
        "rpath",
        &["-Wl,--disable-new-dtags,-rpath,/tmp/syscage-rpath"],
    );
    let runpath_binary = build_fixture("runpath", &["-Wl,-rpath,/tmp/syscage-runpath"]);

    let rpath_report = parse_report(&run_checksec(&rpath_binary));
    let runpath_report = parse_report(&run_checksec(&runpath_binary));

    assert_eq!(rpath_report.get("RPATH").unwrap(), "Enabled");
    assert_eq!(rpath_report.get("RUNPATH").unwrap(), "Disabled");
    assert_eq!(runpath_report.get("RPATH").unwrap(), "Disabled");
    assert_eq!(runpath_report.get("RUNPATH").unwrap(), "Enabled");
}

#[test]
fn stripped_binary_is_reported() {
    let binary = build_fixture("stripped", &["-O2"]);
    let status = Command::new("strip").arg(&binary).status().unwrap();
    assert!(status.success(), "failed to strip fixture");

    let report = parse_report(&run_checksec(&binary));
    assert_eq!(report.get("Stripped").unwrap(), "Enabled");
}

#[test]
fn cet_enabled_binary_reports_shstk_and_ibt_when_toolchain_supports_it() {
    let output_dir = repo_root().join("target").join("checksec-fixtures");
    std::fs::create_dir_all(&output_dir).unwrap();
    let binary = output_dir.join("cet-enabled");
    let source = repo_root().join("tests").join("fixtures").join("checksec_probe.c");

    let status = Command::new("cc")
        .arg(&source)
        .arg("-O2")
        .arg("-fcf-protection=full")
        .arg("-mshstk")
        .arg("-o")
        .arg(&binary)
        .status()
        .unwrap();

    if !status.success() {
        return;
    }

    let report = parse_report(&run_checksec(&binary));
    assert_eq!(report.get("IBT").unwrap(), "Enabled");
    assert_eq!(report.get("SHSTK").unwrap(), "Enabled");
}

#[test]
fn fake_canary_symbol_does_not_trigger_enabled_report() {
    let binary = build_source_fixture(
        "fake-canary",
        "void __stack_chk_fail(void) {}\nint main(void) { return 0; }\n",
        &[
            "-O0",
            "-fno-stack-protector",
            "-no-pie",
            "-U_FORTIFY_SOURCE",
            "-Wl,-z,norelro",
        ],
    );

    let report = parse_report(&run_checksec(&binary));
    assert_eq!(report.get("Canary").unwrap(), "Disabled");
}

#[test]
fn fake_fortify_symbol_does_not_trigger_enabled_report() {
    let binary = build_source_fixture(
        "fake-fortify",
        "int innocent_chk(void) { return 0; }\nint main(void) { return innocent_chk(); }\n",
        &[
            "-O0",
            "-fno-stack-protector",
            "-no-pie",
            "-U_FORTIFY_SOURCE",
            "-Wl,-z,norelro",
        ],
    );

    let report = parse_report(&run_checksec(&binary));
    assert_eq!(report.get("FORTIFY").unwrap(), "Disabled");
}

#[test]
fn explicit_no_cet_flags_report_disabled_features() {
    let binary = build_source_fixture(
        "no-cet",
        "int main(void) { return 0; }\n",
        &[
            "-O0",
            "-fcf-protection=none",
            "-mno-shstk",
            "-fno-stack-protector",
            "-no-pie",
            "-Wl,-z,norelro",
        ],
    );

    let report = parse_report(&run_checksec(&binary));
    assert_eq!(report.get("SHSTK").unwrap(), "Disabled");
    assert_eq!(report.get("IBT").unwrap(), "Disabled");
}

#[test]
fn host_pie_executable_is_reported_consistently() {
    let path = Path::new("/bin/ls");
    if !path.exists() {
        return;
    }

    let report = checksec_report(path);
    assert_eq!(report.get("Arch").unwrap(), "amd64-64-little");
    assert_eq!(report.get("NX").unwrap(), "Enabled");
    assert_eq!(report.get("PIE").unwrap(), "Enabled");
    assert_eq!(report.get("Stripped").unwrap(), "Enabled");
}

#[test]
fn host_shared_object_is_reported_consistently() {
    let path = Path::new("/lib/x86_64-linux-gnu/libc.so.6");
    if !path.exists() {
        return;
    }

    let report = checksec_report(path);
    assert_eq!(report.get("Arch").unwrap(), "amd64-64-little");
    assert_eq!(report.get("NX").unwrap(), "Enabled");
    assert_eq!(report.get("PIE").unwrap(), "Enabled");
    assert_eq!(report.get("Stripped").unwrap(), "Enabled");
}

#[test]
fn non_elf_attachment_is_rejected_without_execution() {
    let path = write_fixture_file("not-elf.bin", b"#!/bin/sh\necho pwned\n");
    let stderr = run_checksec_failure(&path);

    assert!(stderr.contains("is not an ELF file") || stderr.contains("failed to parse"));
}

#[test]
fn truncated_elf_attachment_is_rejected_gracefully() {
    let path = write_fixture_file(
        "truncated-elf.bin",
        &[0x7f, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00],
    );
    let stderr = run_checksec_failure(&path);

    assert!(stderr.contains("failed to parse"));
}

#[test]
fn minimal_elf_header_is_handled_without_panic() {
    let mut data = vec![0u8; 0x40];
    data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    data[4] = 2;
    data[5] = 1;
    data[6] = 1;
    let path = write_fixture_file("corrupted-elf.bin", &data);
    let output = run_checksec(&path);
    let report = parse_report(&output);

    assert!(report.contains_key("Arch"));
    assert!(report.contains_key("RELRO"));
    assert!(report.contains_key("NX"));
}

#[test]
fn synthetic_arch_headers_cover_multiple_architectures() {
    let cases = [
        ("arch-i386.bin", 1, 1, 3u16, "i386-32-little"),
        ("arch-aarch64.bin", 2, 1, 183u16, "aarch64-64-little"),
        ("arch-arm.bin", 1, 1, 40u16, "arm-32-little"),
        ("arch-riscv.bin", 2, 1, 243u16, "riscv-64-little"),
        ("arch-mips-be.bin", 1, 2, 8u16, "MIPS-32-big"),
    ];

    for (name, class, data_encoding, machine, expected_arch) in cases {
        let path = write_minimal_elf(name, class, data_encoding, machine, 2);
        let report = checksec_report(&path);
        assert_eq!(report.get("Arch").unwrap(), expected_arch, "failed for {name}");
    }
}
