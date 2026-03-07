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
                                // println!("Child tries syscall {}", syscall.name());
                                
                                let rdi = regs.rdi;
                                let rsi = regs.rsi;
                                let rdx = regs.rdx;
                                let r10 = regs.r10;
                                let r8 = regs.r8;
                                let r9 = regs.r9;
                                
                                match syscall {
                                    Sysno::prctl => {
                                        println!("prctl({}, {}, {}, {}, {}, {:#X})", rdi, rsi, rdx, r10, r8, r9);
                                    },
                                    Sysno::seccomp => {
                                        
                                        let op = match rdi {
                                            0 => "SECCOMP_SET_MODE_STRICT",
                                            1 => "SECCOMP_SET_MODE_FILTER",
                                            2 => "SECCOMP_GET_ACTION_AVAIL",
                                            3 => "SECCOMP_GET_NOTIF_SIZES",
                                            _ => unreachable!()
                                        };
                                        
                                        let flag = rdi;
                                        
                                        // TODO
                                        // SECCOMP_SET_MODE_FILTER
                                        if rdi == 2 {
                                            
                                        }
                                        
                                        
                                        println!("seccomp({}, {}, {:#X})", op, flag, rdx);
                                    },
                                    _ => {}
                                }
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
