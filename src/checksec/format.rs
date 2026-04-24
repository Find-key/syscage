use std::fmt::Write as _;

use super::model::{ChecksecReport, RelroStatus, Status};

const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RESET: &str = "\x1b[0m";

pub(crate) fn format_report(report: &ChecksecReport) -> String {
    let mut output = String::new();

    writeln!(&mut output, "File: {}", report.path.display()).unwrap();
    writeln!(&mut output, "{:<14} {}", "Arch:", report.arch).unwrap();
    writeln!(
        &mut output,
        "{:<14} {}",
        "RELRO:",
        colorize_relro(&report.relro)
    )
    .unwrap();
    writeln!(
        &mut output,
        "{:<14} {}",
        "SHSTK:",
        colorize_status(&report.shstk)
    )
    .unwrap();
    writeln!(&mut output, "{:<14} {}", "IBT:", colorize_status(&report.ibt)).unwrap();
    writeln!(
        &mut output,
        "{:<14} {}",
        "Canary:",
        colorize_status(&report.canary)
    )
    .unwrap();
    writeln!(&mut output, "{:<14} {}", "NX:", colorize_status(&report.nx)).unwrap();
    writeln!(&mut output, "{:<14} {}", "PIE:", colorize_pie(report)).unwrap();
    writeln!(
        &mut output,
        "{:<14} {}",
        "FORTIFY:",
        colorize_status(&report.fortify)
    )
    .unwrap();
    writeln!(
        &mut output,
        "{:<14} {}",
        "RPATH:",
        colorize_status(&report.rpath)
    )
    .unwrap();
    writeln!(
        &mut output,
        "{:<14} {}",
        "RUNPATH:",
        colorize_status(&report.runpath)
    )
    .unwrap();
    writeln!(
        &mut output,
        "{:<14} {}",
        "Stripped:",
        colorize_status(&report.stripped)
    )
    .unwrap();
    writeln!(&mut output, "{:<14} {}", "RWX:", colorize_status(&report.rwx)).unwrap();

    output
}

fn colorize(text: String, color: &str) -> String {
    format!("{color}{text}{RESET}")
}

fn colorize_status(status: &Status) -> String {
    match status {
        Status::Enabled => colorize(status.as_str().to_string(), GREEN),
        Status::Disabled => colorize(status.as_str().to_string(), RED),
        Status::Unknown => colorize(status.as_str().to_string(), YELLOW),
    }
}

fn colorize_relro(relro: &RelroStatus) -> String {
    match relro {
        RelroStatus::Full => colorize(relro.as_str().to_string(), GREEN),
        RelroStatus::None => colorize(relro.as_str().to_string(), RED),
        RelroStatus::Partial => colorize(relro.as_str().to_string(), YELLOW),
    }
}

fn colorize_pie(report: &ChecksecReport) -> String {
    match report.pie {
        Status::Disabled => {
            let base = report
                .pie_base
                .map(|addr| format!("Disabled (base {addr:#x})"))
                .unwrap_or_else(|| "Disabled".to_string());
            colorize(base, RED)
        }
        Status::Enabled => colorize("Enabled".to_string(), GREEN),
        Status::Unknown => colorize("Unknown".to_string(), YELLOW),
    }
}

#[cfg(test)]
pub(crate) fn strip_ansi(text: &str) -> String {
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{format_report, strip_ansi};
    use crate::checksec::model::{ChecksecReport, RelroStatus, Status};

    #[test]
    fn format_report_prints_expected_fields() {
        let report = ChecksecReport {
            path: PathBuf::from("/tmp/demo"),
            arch: "amd64-64-little".to_string(),
            relro: RelroStatus::Full,
            shstk: Status::Enabled,
            ibt: Status::Enabled,
            canary: Status::Enabled,
            nx: Status::Enabled,
            pie: Status::Enabled,
            fortify: Status::Disabled,
            rpath: Status::Disabled,
            runpath: Status::Disabled,
            stripped: Status::Disabled,
            rwx: Status::Disabled,
            pie_base: Some(0x400000),
        };

        let output = format_report(&report);
        let plain = strip_ansi(&output);
        assert!(output.contains("\x1b[32mFull RELRO\x1b[0m"));
        assert!(plain.contains("File: /tmp/demo"));
        assert!(plain.contains("amd64-64-little"));
        assert!(plain.contains("Full RELRO"));
        assert!(plain.contains("SHSTK:"));
        assert!(plain.contains("IBT:"));
    }

    #[test]
    fn disabled_pie_includes_base_address() {
        let report = ChecksecReport {
            path: PathBuf::from("/tmp/demo"),
            arch: "amd64-64-little".to_string(),
            relro: RelroStatus::None,
            shstk: Status::Disabled,
            ibt: Status::Disabled,
            canary: Status::Disabled,
            nx: Status::Disabled,
            pie: Status::Disabled,
            fortify: Status::Disabled,
            rpath: Status::Disabled,
            runpath: Status::Disabled,
            stripped: Status::Disabled,
            rwx: Status::Disabled,
            pie_base: Some(0x400000),
        };

        let plain = strip_ansi(&format_report(&report));
        assert!(plain.contains("PIE:           Disabled (base 0x400000)"));
    }
}
