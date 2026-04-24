use anyhow::{bail, Context, Result};
use goblin::elf::dynamic;
use goblin::elf::header;
use goblin::elf::note;
use goblin::elf::program_header;
use goblin::elf::Elf;
use goblin::Object;
use std::fs;
use std::path::Path;

use super::model::{ChecksecReport, RelroStatus, Status};

pub(crate) fn analyze(path: impl AsRef<Path>) -> Result<ChecksecReport> {
    let path = path.as_ref().to_path_buf();
    let data = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;

    let elf = match Object::parse(&data)
        .with_context(|| format!("failed to parse {}", path.display()))?
    {
        Object::Elf(elf) => elf,
        _ => bail!("{} is not an ELF file", path.display()),
    };
    let (shstk, ibt) = detect_x86_cet(&elf, &data);

    Ok(ChecksecReport {
        path,
        arch: describe_arch(elf.header.e_machine, elf.is_64, elf.little_endian),
        relro: detect_relro(&elf),
        shstk,
        ibt,
        canary: detect_canary(&elf),
        nx: detect_nx(&elf),
        pie: detect_pie(&elf),
        fortify: detect_fortify(&elf),
        rpath: detect_rpath(&elf),
        runpath: detect_runpath(&elf),
        stripped: detect_stripped(&elf),
        rwx: detect_rwx(&elf),
        pie_base: detect_base_address(&elf),
    })
}

fn describe_arch(machine: u16, is_64: bool, little_endian: bool) -> String {
    let bits = if is_64 { "64" } else { "32" };
    let endian = if little_endian { "little" } else { "big" };
    let arch = match machine {
        header::EM_X86_64 => "amd64",
        header::EM_386 => "i386",
        header::EM_AARCH64 => "aarch64",
        header::EM_ARM => "arm",
        header::EM_RISCV => "riscv",
        _ => header::machine_to_str(machine),
    };

    format!("{arch}-{bits}-{endian}")
}

fn detect_relro(elf: &Elf<'_>) -> RelroStatus {
    let has_gnu_relro = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == program_header::PT_GNU_RELRO);
    if !has_gnu_relro {
        return RelroStatus::None;
    }

    let bind_now = elf.dynamic.as_ref().is_some_and(|dynamic_section| {
        dynamic_section.info.flags & dynamic::DF_BIND_NOW != 0
            || dynamic_section.info.flags_1 & dynamic::DF_1_NOW != 0
            || dynamic_section
                .dyns
                .iter()
                .any(|entry| entry.d_tag == dynamic::DT_BIND_NOW)
    });

    if bind_now {
        RelroStatus::Full
    } else {
        RelroStatus::Partial
    }
}

fn detect_canary(elf: &Elf<'_>) -> Status {
    let has_canary = referenced_dyn_symbol_names(elf).any(is_canary_symbol)
        || (defined_symbol_names(elf).any(|name| name == "__stack_chk_fail")
            && defined_symbol_names(elf).any(|name| name == "__stack_chk_fail_local"));

    if has_canary {
        Status::Enabled
    } else {
        Status::Disabled
    }
}

fn detect_x86_cet(elf: &Elf<'_>, data: &[u8]) -> (Status, Status) {
    if elf.header.e_machine != header::EM_X86_64 && elf.header.e_machine != header::EM_386 {
        return (Status::Unknown, Status::Unknown);
    }

    const GNU_PROPERTY_X86_FEATURE_1_AND: u32 = 0xc000_0002;
    const GNU_PROPERTY_X86_FEATURE_1_IBT: u32 = 1 << 0;
    const GNU_PROPERTY_X86_FEATURE_1_SHSTK: u32 = 1 << 1;

    let mut features = 0u32;
    let alignment = if elf.is_64 { 8 } else { 4 };

    if let Some(notes) = elf.iter_note_sections(data, Some(".note.gnu.property")) {
        for note_result in notes {
            let Ok(note) = note_result else {
                continue;
            };
            if note.name != "GNU" || note.n_type != note::NT_GNU_PROPERTY_TYPE_0 {
                continue;
            }

            let mut offset = 0usize;
            while offset + 8 <= note.desc.len() {
                let property_type = read_u32(&note.desc[offset..offset + 4], elf.little_endian);
                let data_size = read_u32(&note.desc[offset + 4..offset + 8], elf.little_endian) as usize;
                offset += 8;

                if offset + data_size > note.desc.len() {
                    break;
                }

                if property_type == GNU_PROPERTY_X86_FEATURE_1_AND && data_size >= 4 {
                    features |= read_u32(&note.desc[offset..offset + 4], elf.little_endian);
                }

                offset += data_size;
                let padding = offset % alignment;
                if padding != 0 {
                    offset += alignment - padding;
                }
            }
        }
    }

    let ibt = if features & GNU_PROPERTY_X86_FEATURE_1_IBT != 0 {
        Status::Enabled
    } else {
        Status::Disabled
    };
    let shstk = if features & GNU_PROPERTY_X86_FEATURE_1_SHSTK != 0 {
        Status::Enabled
    } else {
        Status::Disabled
    };

    (shstk, ibt)
}

fn read_u32(bytes: &[u8], little_endian: bool) -> u32 {
    let raw: [u8; 4] = bytes.try_into().unwrap();
    if little_endian {
        u32::from_le_bytes(raw)
    } else {
        u32::from_be_bytes(raw)
    }
}

fn detect_nx(elf: &Elf<'_>) -> Status {
    let gnu_stack = elf
        .program_headers
        .iter()
        .find(|ph| ph.p_type == program_header::PT_GNU_STACK);

    match gnu_stack {
        Some(ph) if ph.p_flags & program_header::PF_X != 0 => Status::Disabled,
        Some(_) => Status::Enabled,
        None => Status::Unknown,
    }
}

fn detect_pie(elf: &Elf<'_>) -> Status {
    match elf.header.e_type {
        header::ET_DYN => Status::Enabled,
        header::ET_EXEC => Status::Disabled,
        _ => Status::Unknown,
    }
}

fn detect_base_address(elf: &Elf<'_>) -> Option<u64> {
    if detect_pie(elf) != Status::Disabled {
        return None;
    }

    elf.program_headers
        .iter()
        .filter(|ph| ph.p_type == program_header::PT_LOAD)
        .map(|ph| ph.p_vaddr)
        .min()
}

fn detect_fortify(elf: &Elf<'_>) -> Status {
    let fortified = referenced_dyn_symbol_names(elf).any(is_fortify_symbol)
        || (defined_symbol_names(elf).any(is_fortify_chk_symbol)
            && defined_symbol_names(elf).any(|name| matches!(name, "__fortify_fail" | "__chk_fail")));

    if fortified {
        Status::Enabled
    } else {
        Status::Disabled
    }
}

fn detect_rpath(elf: &Elf<'_>) -> Status {
    if elf.rpaths.is_empty() {
        Status::Disabled
    } else {
        Status::Enabled
    }
}

fn detect_runpath(elf: &Elf<'_>) -> Status {
    if elf.runpaths.is_empty() {
        Status::Disabled
    } else {
        Status::Enabled
    }
}

fn detect_stripped(elf: &Elf<'_>) -> Status {
    if elf.syms.is_empty() {
        Status::Enabled
    } else {
        Status::Disabled
    }
}

fn detect_rwx(elf: &Elf<'_>) -> Status {
    let has_rwx = elf.program_headers.iter().any(|ph| {
        ph.p_type == program_header::PT_LOAD
            && ph.p_flags & program_header::PF_R != 0
            && ph.p_flags & program_header::PF_W != 0
            && ph.p_flags & program_header::PF_X != 0
    });

    if has_rwx {
        Status::Enabled
    } else {
        Status::Disabled
    }
}

fn referenced_dyn_symbol_names<'a>(elf: &'a Elf<'a>) -> impl Iterator<Item = &'a str> + 'a {
    elf.dynrelas
        .iter()
        .chain(elf.dynrels.iter())
        .chain(elf.pltrelocs.iter())
        .filter_map(|reloc| elf.dynsyms.get(reloc.r_sym))
        .filter(|sym| sym.is_import())
        .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name))
}

fn defined_symbol_names<'a>(elf: &'a Elf<'a>) -> impl Iterator<Item = &'a str> + 'a {
    let dynsyms = elf
        .dynsyms
        .iter()
        .filter(|sym| !sym.is_import())
        .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name));
    let syms = elf
        .syms
        .iter()
        .filter(|sym| sym.st_shndx != 0)
        .filter_map(|sym| elf.strtab.get_at(sym.st_name));

    dynsyms.chain(syms)
}

fn is_canary_symbol(name: &str) -> bool {
    matches!(
        name,
        "__stack_chk_fail"
            | "__stack_chk_fail_local"
            | "__stack_chk_guard"
            | "__intel_security_cookie"
    )
}

fn is_fortify_symbol(name: &str) -> bool {
    is_fortify_chk_symbol(name) || matches!(name, "__fortify_fail" | "__chk_fail")
}

fn is_fortify_chk_symbol(name: &str) -> bool {
    name.starts_with("__") && name.ends_with("_chk")
}

#[cfg(test)]
mod tests {
    use goblin::elf::header;

    use super::describe_arch;

    #[test]
    fn architecture_string_uses_pwntools_style() {
        assert_eq!(
            describe_arch(header::EM_X86_64, true, true),
            "amd64-64-little"
        );
    }
}
