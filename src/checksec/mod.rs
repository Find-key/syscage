mod format;
mod model;
mod parser;

use anyhow::Result;

use self::format::format_report;
use self::parser::analyze;

pub fn check(elf: String) -> Result<()> {
    let report = analyze(&elf)?;
    print!("{}", format_report(&report));
    Ok(())
}
