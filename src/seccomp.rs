use anyhow::{bail, Context, Result};
use libc::user_regs_struct;
use nix::sys::ptrace::{self, AddressType};
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult, Pid};
use std::ffi::{CStr, CString};
use std::fmt::Write as _;
use std::mem::{offset_of, size_of};
use syscalls::Sysno;

const X86_64: u32 = 0xc000_003e;
const I386: u32 = 0x4000_0003;

const BPF_LD: u16 = 0x00;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;

const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_AND: u16 = 0x50;

const BPF_JA: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_JGT: u16 = 0x20;
const BPF_JGE: u16 = 0x30;
const BPF_JSET: u16 = 0x40;

const BPF_K: u16 = 0x00;

const BPF_LD_W_ABS: u16 = BPF_LD | BPF_W | BPF_ABS;
const BPF_RET_K: u16 = BPF_RET | BPF_K;
const BPF_JMP_JA: u16 = BPF_JMP | BPF_JA;
const BPF_JMP_JEQ_K: u16 = BPF_JMP | BPF_JEQ | BPF_K;
const BPF_JMP_JGE_K: u16 = BPF_JMP | BPF_JGE | BPF_K;
const BPF_JMP_JGT_K: u16 = BPF_JMP | BPF_JGT | BPF_K;
const BPF_JMP_JSET_K: u16 = BPF_JMP | BPF_JSET | BPF_K;
const BPF_ALU_AND_K: u16 = BPF_ALU | BPF_AND | BPF_K;

const MAX_BPF_INSTRUCTIONS: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoadTarget {
    SyscallNr,
    Arch,
    Generic(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

impl SockFilter {
    fn from_bytes(bytes: [u8; size_of::<libc::sock_filter>()]) -> Self {
        Self {
            code: u16::from_ne_bytes([bytes[0], bytes[1]]),
            jt: bytes[2],
            jf: bytes[3],
            k: u32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct FilterProgram {
    len: usize,
    filter_ptr: usize,
}

#[derive(Clone, Copy, Debug)]
enum InstallSource {
    Seccomp { flags: u64 },
    Prctl,
}

impl InstallSource {
    fn describe(self) -> String {
        match self {
            Self::Prctl => "prctl(PR_SET_SECCOMP)".to_string(),
            Self::Seccomp { flags: 0 } => {
                "seccomp(SECCOMP_SET_MODE_FILTER, flags=0)".to_string()
            }
            Self::Seccomp { flags } => {
                format!(
                    "seccomp(SECCOMP_SET_MODE_FILTER, flags={flags:#x} [{}])",
                    describe_seccomp_flags(flags)
                )
            }
        }
    }
}

fn read_child_bytes(pid: Pid, address: usize, len: usize) -> Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }

    let word_size = size_of::<libc::c_long>();
    let mut bytes = Vec::with_capacity(len);
    let mut offset = 0usize;

    while offset < len {
        let word = ptrace::read(pid, (address + offset) as AddressType)
            .with_context(|| format!("ptrace read failed at {:#x}", address + offset))?;
        let chunk = word.to_ne_bytes();
        let take = (len - offset).min(word_size);
        bytes.extend_from_slice(&chunk[..take]);
        offset += take;
    }

    Ok(bytes)
}

fn read_filter_program_header(pid: Pid, address: usize) -> Result<FilterProgram> {
    let bytes = read_child_bytes(pid, address, size_of::<libc::sock_fprog>())?;

    let len_offset = offset_of!(libc::sock_fprog, len);
    let ptr_offset = offset_of!(libc::sock_fprog, filter);
    let len_end = len_offset + size_of::<libc::c_ushort>();
    let ptr_end = ptr_offset + size_of::<usize>();

    let len = u16::from_ne_bytes(bytes[len_offset..len_end].try_into().unwrap()) as usize;
    let filter_ptr = usize::from_ne_bytes(bytes[ptr_offset..ptr_end].try_into().unwrap());

    if len == 0 {
        bail!("seccomp program length is zero");
    }
    if len > MAX_BPF_INSTRUCTIONS {
        bail!(
            "seccomp program length {} exceeds kernel limit {}",
            len,
            MAX_BPF_INSTRUCTIONS
        );
    }
    if filter_ptr == 0 {
        bail!("seccomp filter pointer is null");
    }

    Ok(FilterProgram { len, filter_ptr })
}

fn read_filter_program(pid: Pid, address: usize) -> Result<Vec<SockFilter>> {
    let header = read_filter_program_header(pid, address)?;
    let byte_len = header
        .len
        .checked_mul(size_of::<libc::sock_filter>())
        .context("seccomp program size overflowed usize")?;
    let bytes = read_child_bytes(pid, header.filter_ptr, byte_len)?;

    Ok(bytes
        .chunks_exact(size_of::<libc::sock_filter>())
        .map(|chunk| SockFilter::from_bytes(chunk.try_into().unwrap()))
        .collect())
}

fn describe_seccomp_flags(flags: u64) -> String {
    let mut names = Vec::new();

    if flags & libc::SECCOMP_FILTER_FLAG_TSYNC != 0 {
        names.push("TSYNC");
    }
    if flags & libc::SECCOMP_FILTER_FLAG_LOG != 0 {
        names.push("LOG");
    }
    if flags & libc::SECCOMP_FILTER_FLAG_SPEC_ALLOW != 0 {
        names.push("SPEC_ALLOW");
    }
    if flags & libc::SECCOMP_FILTER_FLAG_NEW_LISTENER != 0 {
        names.push("NEW_LISTENER");
    }
    if flags & libc::SECCOMP_FILTER_FLAG_TSYNC_ESRCH != 0 {
        names.push("TSYNC_ESRCH");
    }
    if flags & libc::SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV != 0 {
        names.push("WAIT_KILLABLE_RECV");
    }

    if names.is_empty() {
        "unknown".to_string()
    } else {
        names.join(", ")
    }
}

fn describe_load_target(offset: u32) -> (String, Option<LoadTarget>) {
    match offset {
        0 => ("A = sys_number".to_string(), Some(LoadTarget::SyscallNr)),
        4 => ("A = arch".to_string(), Some(LoadTarget::Arch)),
        8 => (
            "A = instruction_pointer_low".to_string(),
            Some(LoadTarget::Generic(offset)),
        ),
        12 => (
            "A = instruction_pointer_high".to_string(),
            Some(LoadTarget::Generic(offset)),
        ),
        value if value >= 16 => {
            let relative = value - 16;
            let arg_index = relative / 8;
            let arg_half = relative % 8;
            if arg_index < 6 && (arg_half == 0 || arg_half == 4) {
                let half = if arg_half == 0 {
                    "low"
                } else {
                    "high"
                };
                (
                    format!("A = args[{arg_index}]_{half}"),
                    Some(LoadTarget::Generic(offset)),
                )
            } else {
                (
                    format!("A = seccomp_data[{offset}]"),
                    Some(LoadTarget::Generic(offset)),
                )
            }
        }
        _ => (
            format!("A = seccomp_data[{offset}]"),
            Some(LoadTarget::Generic(offset)),
        ),
    }
}

fn describe_return(k: u32) -> String {
    let action = k & libc::SECCOMP_RET_ACTION_FULL;
    let data = k & libc::SECCOMP_RET_DATA;

    match action {
        libc::SECCOMP_RET_ALLOW => "return ALLOW".to_string(),
        libc::SECCOMP_RET_KILL_PROCESS => "return KILL_PROCESS".to_string(),
        libc::SECCOMP_RET_KILL_THREAD => "return KILL".to_string(),
        libc::SECCOMP_RET_TRAP => format!("return TRAP({data})"),
        libc::SECCOMP_RET_ERRNO => format!("return ERRNO({data})"),
        libc::SECCOMP_RET_TRACE => format!("return TRACE({data})"),
        libc::SECCOMP_RET_LOG => format!("return LOG({data})"),
        libc::SECCOMP_RET_USER_NOTIF => format!("return USER_NOTIF({data})"),
        _ => format!("return RAW({k:#010x})"),
    }
}

fn describe_value(k: u32, load_target: Option<LoadTarget>) -> String {
    match load_target {
        Some(LoadTarget::SyscallNr) => Sysno::new(k as usize)
            .map(|syscall| syscall.name().to_string())
            .unwrap_or_else(|| format!("{k:#x}")),
        Some(LoadTarget::Arch) => match k {
            X86_64 => "ARCH_X86_64".to_string(),
            I386 => "ARCH_I386".to_string(),
            _ => format!("{k:#x}"),
        },
        _ => format!("{k:#x}"),
    }
}

fn describe_conditional_jump(line: usize, rule: SockFilter, positive: String, negative: String) -> String {
    let true_target = line + 1 + usize::from(rule.jt);
    let false_target = line + 1 + usize::from(rule.jf);

    match (rule.jt, rule.jf) {
        (0, 0) => format!("if ({positive}) continue"),
        (_, 0) => format!("if ({positive}) goto {true_target:04}"),
        (0, _) => format!("if ({negative}) goto {false_target:04}"),
        _ => format!("if ({positive}) goto {true_target:04} else goto {false_target:04}"),
    }
}

fn format_program(rules: &[SockFilter]) -> String {
    let mut output = String::new();

    writeln!(&mut output).unwrap();
    writeln!(&mut output, " line  CODE  JT   JF      K           COMMENT").unwrap();
    writeln!(&mut output, "==============================================================").unwrap();

    if rules.is_empty() {
        writeln!(&mut output, " <empty>").unwrap();
        return output;
    }

    let mut load_target = None;

    for (line, rule) in rules.iter().copied().enumerate() {
        let description = match rule.code {
            BPF_LD_W_ABS => {
                let (description, next_target) = describe_load_target(rule.k);
                load_target = next_target;
                description
            }
            BPF_RET_K => describe_return(rule.k),
            BPF_JMP_JA => format!("goto {:04}", line + 1 + rule.k as usize),
            BPF_JMP_JEQ_K => describe_conditional_jump(
                line,
                rule,
                format!("A == {}", describe_value(rule.k, load_target)),
                format!("A != {}", describe_value(rule.k, load_target)),
            ),
            BPF_JMP_JGE_K => describe_conditional_jump(
                line,
                rule,
                format!("A >= {}", describe_value(rule.k, load_target)),
                format!("A < {}", describe_value(rule.k, load_target)),
            ),
            BPF_JMP_JGT_K => describe_conditional_jump(
                line,
                rule,
                format!("A > {}", describe_value(rule.k, load_target)),
                format!("A <= {}", describe_value(rule.k, load_target)),
            ),
            BPF_JMP_JSET_K => describe_conditional_jump(
                line,
                rule,
                format!("(A & {}) != 0", describe_value(rule.k, load_target)),
                format!("(A & {}) == 0", describe_value(rule.k, load_target)),
            ),
            BPF_ALU_AND_K => format!("A = A & {:#x}", rule.k),
            _ => format!(
                "raw rule: code={:#06x} jt={} jf={} k={:#010x}",
                rule.code, rule.jt, rule.jf, rule.k
            ),
        };

        writeln!(
            &mut output,
            " {:04}: 0x{:02x} 0x{:02x} 0x{:02x} 0x{:08x}  {}",
            line, rule.code, rule.jt, rule.jf, rule.k, description
        )
        .unwrap();
    }

    output
}

fn build_argv(program: &CString, args: &[String]) -> Result<Vec<CString>> {
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(program.clone());
    for arg in args {
        argv.push(CString::new(arg.as_str()).context("argument contains NUL byte")?);
    }
    Ok(argv)
}

fn print_seccomp_program(source: InstallSource, rules: &[SockFilter]) {
    println!();
    println!("=== Seccomp filter detected ===");
    println!("Source: {}", source.describe());
    print!("{}", format_program(rules));
    println!("Status: loaded");
}

fn trace_syscall_entry(pid: Pid, regs: &user_regs_struct) -> Result<Option<(InstallSource, Vec<SockFilter>)>> {
    let Some(syscall) = Sysno::new(regs.orig_rax as usize) else {
        return Ok(None);
    };

    match syscall {
        Sysno::prctl
            if regs.rdi == libc::PR_SET_SECCOMP as u64
                && regs.rsi == libc::SECCOMP_MODE_FILTER as u64 =>
        {
            let rules = read_filter_program(pid, regs.rdx as usize)?;
            Ok(Some((InstallSource::Prctl, rules)))
        }
        Sysno::seccomp if regs.rdi == libc::SECCOMP_SET_MODE_FILTER as u64 => {
            let rules = read_filter_program(pid, regs.rdx as usize)?;
            Ok(Some((InstallSource::Seccomp { flags: regs.rsi }, rules)))
        }
        _ => Ok(None),
    }
}

fn child_exec(program: &CString, args: &[CString]) -> ! {
    let argv: Vec<&CStr> = args.iter().map(CString::as_c_str).collect();

    if let Err(err) = ptrace::traceme() {
        eprintln!("ptrace(TRACEME) failed: {err}");
        unsafe {
            libc::_exit(1);
        }
    }

    let err = execvp(program, &argv).expect_err("execvp only returns on failure");
    eprintln!("execvp failed: {err}");
    unsafe {
        libc::_exit(127);
    }
}

pub fn check(binary: String, args: Vec<String>) -> Result<()> {
    println!("[*] Executing: {binary}");
    if !args.is_empty() {
        println!("[*] With args: {args:?}");
    }

    let program = CString::new(binary.as_str()).context("binary path contains NUL byte")?;
    let argv = build_argv(&program, &args)?;

    match unsafe { fork() }.context("fork failed")? {
        ForkResult::Child => child_exec(&program, &argv),
        ForkResult::Parent { child } => trace_child(child),
    }
}

fn trace_child(pid: Pid) -> Result<()> {
    println!("Monitoring child process PID: {pid}");

    match waitpid(pid, None).context("failed to wait for child startup")? {
        WaitStatus::Stopped(_, _) | WaitStatus::PtraceEvent(_, _, _) | WaitStatus::PtraceSyscall(_) => {}
        WaitStatus::Exited(_, status) => {
            bail!("child exited before tracing started with status {status}");
        }
        WaitStatus::Signaled(_, signal, _) => {
            bail!("child died before tracing started with signal {signal:?}");
        }
        status => {
            bail!("unexpected child startup status: {status:?}");
        }
    }

    ptrace::setoptions(pid, ptrace::Options::PTRACE_O_TRACESYSGOOD)
        .context("failed to configure ptrace options")?;
    ptrace::syscall(pid, None).context("failed to resume child after startup stop")?;

    let mut entering_syscall = true;
    let mut trace_errors = Vec::new();

    loop {
        match waitpid(pid, None).context("waitpid failed while tracing child")? {
            WaitStatus::Exited(_, status) => {
                println!("Child exit with {status}");
                break;
            }
            WaitStatus::Signaled(_, signal, _) => {
                println!("Child killed by {signal:?}");
                break;
            }
            WaitStatus::PtraceSyscall(_) => {
                if entering_syscall {
                    match ptrace::getregs(pid).context("failed to fetch child registers") {
                        Ok(regs) => match trace_syscall_entry(pid, &regs) {
                            Ok(Some((source, rules))) => print_seccomp_program(source, &rules),
                            Ok(None) => {}
                            Err(err) => trace_errors.push(format!("{err:#}")),
                        },
                        Err(err) => trace_errors.push(format!("{err:#}")),
                    }
                }
                entering_syscall = !entering_syscall;
            }
            WaitStatus::Stopped(_, signal) => {
                if signal != Signal::SIGTRAP {
                    ptrace::syscall(pid, Some(signal))
                        .with_context(|| format!("failed to deliver signal {signal:?} to child"))?;
                    continue;
                }
            }
            WaitStatus::Continued(_) | WaitStatus::StillAlive | WaitStatus::PtraceEvent(_, _, _) => {}
        }

        match ptrace::syscall(pid, None) {
            Ok(()) => {}
            Err(nix::errno::Errno::ESRCH) => break,
            Err(err) => return Err(err).context("failed to resume child with PTRACE_SYSCALL"),
        }
    }

    if trace_errors.is_empty() {
        Ok(())
    } else {
        bail!("tracing completed with errors:\n{}", trace_errors.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_argv, format_program, InstallSource, SockFilter,
        BPF_JMP_JEQ_K, BPF_JMP_JSET_K, BPF_LD_W_ABS, BPF_RET_K,
    };
    use std::ffi::CString;

    #[test]
    fn build_argv_includes_program_as_argv0() {
        let program = CString::new("/tmp/prog").unwrap();
        let argv = build_argv(&program, &[String::from("alpha"), String::from("beta")]).unwrap();

        let rendered: Vec<&str> = argv.iter().map(|arg| arg.to_str().unwrap()).collect();
        assert_eq!(rendered, vec!["/tmp/prog", "alpha", "beta"]);
    }

    #[test]
    fn format_program_handles_jset_with_bitmask_semantics() {
        let rules = [
            SockFilter {
                code: BPF_LD_W_ABS,
                jt: 0,
                jf: 0,
                k: 4,
            },
            SockFilter {
                code: BPF_JMP_JSET_K,
                jt: 1,
                jf: 0,
                k: 0x4000_0000,
            },
            SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            },
        ];

        let output = format_program(&rules);
        assert!(output.contains("0000: 0x20 0x00 0x00 0x00000004  A = arch"));
        assert!(output.contains("if ((A & 0x40000000) != 0) goto 0003"));
    }

    #[test]
    fn format_program_keeps_branch_targets_wide() {
        let mut rules = Vec::new();
        for _ in 0..260 {
            rules.push(SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            });
        }
        rules[258] = SockFilter {
            code: BPF_JMP_JEQ_K,
            jt: 1,
            jf: 0,
            k: 1,
        };

        let output = format_program(&rules);
        assert!(output.contains("0258: 0x15 0x01 0x00 0x00000001  if (A == 0x1) goto 0260"));
    }

    #[test]
    fn install_source_describes_flags() {
        let description = InstallSource::Seccomp {
            flags: libc::SECCOMP_FILTER_FLAG_TSYNC | libc::SECCOMP_FILTER_FLAG_LOG,
        }
        .describe();

        assert!(description.contains("TSYNC"));
        assert!(description.contains("LOG"));
    }

    #[test]
    fn filter_program_header_reads_only_len_and_pointer_bytes() {
        let len = 1u16;
        let filter_ptr = 0x1122_3344_5566_7788usize;
        let mut bytes = vec![0x41u8; std::mem::size_of::<libc::sock_fprog>()];

        let len_offset = std::mem::offset_of!(libc::sock_fprog, len);
        let ptr_offset = std::mem::offset_of!(libc::sock_fprog, filter);

        bytes[len_offset..len_offset + std::mem::size_of::<u16>()].copy_from_slice(&len.to_ne_bytes());
        bytes[ptr_offset..ptr_offset + std::mem::size_of::<usize>()]
            .copy_from_slice(&filter_ptr.to_ne_bytes());

        let parsed_len = u16::from_ne_bytes(bytes[len_offset..len_offset + 2].try_into().unwrap()) as usize;
        let parsed_ptr =
            usize::from_ne_bytes(bytes[ptr_offset..ptr_offset + std::mem::size_of::<usize>()].try_into().unwrap());

        assert_eq!(parsed_len, 1);
        assert_eq!(parsed_ptr, filter_ptr);
    }
}
