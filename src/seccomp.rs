use anyhow::Result;
use nix::sys::ptrace::{self, AddressType};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult, Pid};
use syscalls::Sysno;
use std::ffi::{CString, CStr};
use libc::{PR_SET_NO_NEW_PRIVS, SECCOMP_SET_MODE_FILTER, user_regs_struct};

#[allow(unused)]
pub mod bpf {
    pub const BPF_LD   : u8 = 0x00;
    pub const BPF_JMP  : u8 = 0x05;
    pub const BPF_RER  : u8 = 0x06;
    
    pub const BPF_W    : u8 = 0x00;
    
    pub const BPF_ABS  : u8 = 0x20;
    
    pub const BPF_JA   : u8 = 0x00;
    pub const BPF_JEQ  : u8 = 0x10;
    pub const BPF_JGT  : u8 = 0x20;
    pub const BPF_JGE  : u8 = 0x30;
    pub const BPF_JSET : u8 = 0x40;
}

struct SockFilter {
    code : u16,
    jt : u8,
    jf : u8,
    k : u32
}

impl SockFilter {
    fn new(rule: u64) -> Self {
        SockFilter { 
            code: (rule & 0xffff) as u16, 
            jt: ((rule >> 16) & 0xff) as u8, 
            jf: ((rule >> 24) & 0xff) as u8, 
            k: (rule >> 32) as u32 
        }
    }
    
    fn create(pid: Pid, address: AddressType) -> Self {
        let rule = ptrace::read(pid, address).unwrap() as u64;
        
        Self::new(rule)
    }
    
    fn create_all(pid: Pid, address: AddressType) -> Vec<Self> {
        let len = ptrace::read(pid, address).unwrap();
        let filter_ptr = ptrace::read(pid, (address as u64 + 8) as AddressType).unwrap() as i64;
        
        (0..len)
            .map(|i| Self::create(pid, (filter_ptr + 8*i) as AddressType))
            .collect()
    }
    
    fn print_raw(self: &Self) {
        println!("{:#06X} {:#04X} {:#04X} {:#010X}", self.code, self.jt, self.jf, self.k);
    }
}

fn is_set_no_new_prevs(regs: &user_regs_struct) -> bool {
    regs.rdi == PR_SET_NO_NEW_PRIVS as u64
    && regs.rsi == 1
    && regs.rdx == 0
    && regs.r10 == 0
    && regs.r8 == 0
}



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
                                
                                match syscall {
                                    Sysno::prctl => {
                                        if is_set_no_new_prevs(&regs) {
                                            println!("Clear the prev filter!")
                                        }
                                                                                
                                    },
                                    Sysno::seccomp => {
                                        
                                        let op = regs.rdi;
                                        let flags = regs.rsi;
                                        
                                        if op == SECCOMP_SET_MODE_FILTER as u64 && flags == 0 {
                                            let rules : Vec<SockFilter> = SockFilter::create_all(pid, regs.rdx as AddressType);
                                            
                                            for rule in rules {
                                                rule.print_raw();
                                            }
                                            println!("Seccomp load!")
                                        }
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
