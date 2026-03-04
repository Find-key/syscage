use anyhow::Result;

pub fn check(binary: String, args: Vec<String>) -> Result<()> {
    println!("[*] Executing: {}", binary);

    if !args.is_empty() {
        println!("[*] With args: {:?}", args);
    }

    // TODO:
    // 1. fork
    // 2. ptrace TRACEME
    // 3. execve target
    // 4. parent wait
    // 5. PTRACE_SECCOMP_GET_FILTER
    // 6. dump BPF

    println!("[!] seccomp extraction not implemented yet");

    Ok(())
}
