use anyhow::Result;

use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult};
use syscalls::Sysno;
use std::ffi::{CString, CStr};

pub fn check(binary: String, args: Vec<String>) -> Result<()> {
    println!("[*] Executing: {}", binary);

    if !args.is_empty() {
        println!("[*] With args: {:?}", args);
    }

    // TODO:
    // 1. fork  ✔
    // 2. ptrace TRACEME
    // 3. execve target
    // 4. parent wait
    // 5. PTRACE_SECCOMP_GET_FILTER
    // 6. dump BPF

    let program: CString = CString::new(binary.as_str()).unwrap();
    let arguments: Vec<CString> = args
                                .iter()
                                .map(|arg| CString::new(arg.as_str()).unwrap())
                                .collect();
    
    let arguments_ref: Vec<&CStr> = arguments
                                .iter()
                                .map(|arg| arg.as_c_str())
                                .collect();
    
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            ptrace::traceme().expect("Traceme failed");
            
            execvp(&program, &arguments_ref).unwrap();
        },
        Ok(ForkResult::Parent{ child }) => {
            let pid = child; 
            let mut entering = true;
            println!("Monitoring child process PID: {}", child);
            
            waitpid(pid, None).unwrap();
            
            ptrace::setoptions(
                pid,
                ptrace::Options::PTRACE_O_TRACESYSGOOD
            ).unwrap();
            
            ptrace::syscall(pid, None).unwrap();
            
            loop {
                match waitpid(pid, None).unwrap() {
                    WaitStatus::Exited(_, status) => {
                        println!("Child exit with {}", status);
                        break;
                    },
                    WaitStatus::PtraceSyscall(_) => {
                        if entering {
                            let regs = ptrace::getregs(pid).unwrap();
            
                            if let Some(syscall) = Sysno::new(regs.orig_rax as usize) {
                                println!("Child tries syscall {}", syscall.name());
                            }
                        }
            
                        entering = !entering;
                        
                    },
                    _ => {}
                }
                ptrace::syscall(pid, None).unwrap();
            }
            
            
        },
        Err(_) => {
            println!("Fork failed")
        }
    }
    
    
    println!("[!] seccomp extraction not implemented yet");

    Ok(())
}
