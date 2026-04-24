use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "syscage")]
#[command(version = "0.1")]
#[command(about = "A minimal seccomp analysis tool written in Rust")]
pub struct Syscage {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Execute a program and dump its seccomp filter
    Check {
        /// Target executable
        binary: String,

        /// Arguments passed to the program
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Inspect an ELF file and report its architecture and enabled hardening
    Checksec {
        /// Target ELF file
        elf: String,
    },
}

impl Syscage {
    pub fn run(self) -> anyhow::Result<()> {
        match self.command {
            Commands::Check { binary, args } => crate::seccomp::check(binary, args),
            Commands::Checksec { elf } => crate::checksec::check(elf),
            // 以后增加新命令，只需要在这里扩充
        }
    }
}
