mod cli;
mod seccomp;

use anyhow::Result;
use cli::Syscage;
use clap::Parser;

fn main() -> Result<()> {
    let cage = Syscage::parse();
    cage.run()?;

    Ok(())
}
