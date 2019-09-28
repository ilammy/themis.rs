// Copyright 2018 Google LLC
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

//! Build BoringSSL static library with properly renamed symbols.

use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::env;
use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::process::{Command, Stdio};

use goblin::{self, elf, mach};

// Relative to CARGO_MANIFEST_DIR
const BORINGSSL_SRC: &str = "boringssl";

// Relative to OUT_DIR
const BUILD_DIR_1: &str = "boringssl/build_1";
const BUILD_DIR_2: &str = "boringssl/build_2";
const SYMBOL_FILE: &str = "boringssl/symbols.txt";

fn env(name: &str) -> String {
    let var = env::var(name).expect(&format!("missing required environment variable {}", name));
    println!("cargo:rerun-if-env-changed={}", var);
    var
}

fn main() {
    validate_dependencies();

    let manifest_dir = env("CARGO_MANIFEST_DIR");
    let abs_boringssl_src = format!("{}/{}", manifest_dir, BORINGSSL_SRC);

    let out_dir = env("OUT_DIR");
    let abs_build_dir_1 = format!("{}/{}", out_dir, BUILD_DIR_1);
    let abs_build_dir_2 = format!("{}/{}", out_dir, BUILD_DIR_2);
    let abs_symbol_file = format!("{}/{}", out_dir, SYMBOL_FILE);

    fs::create_dir_all(&abs_build_dir_1).expect("failed to create first build directory");
    fs::create_dir_all(&abs_build_dir_2).expect("failed to create second build directory");

    let major = env("CARGO_PKG_VERSION_MAJOR");
    let minor = env("CARGO_PKG_VERSION_MINOR");
    let patch = env("CARGO_PKG_VERSION_PATCH");
    let version_string = format!("{}_{}_{}", major, minor, patch);
    let prefix = format!("__SOTER_BORINGSSL_{}", version_string);
    let cmake_version_flag = format!("-DBORINGSSL_PREFIX={}", prefix);
    let cmake_symbol_listing = "-DBORINGSSL_PREFIX_SYMBOLS=../symbols.txt";

    //
    // We build BoringSSL twice. First we run a build to determine what symbols are available.
    //

    // If we've already run a build in a directory, then we need to build with the same tool.
    let build_with = match built_with(&abs_build_dir_1) {
        Some(prior_build_system) => prior_build_system,
        None => {
            if have_ninja() {
                BuildSystem::Ninja
            } else {
                BuildSystem::Make
            }
        }
    };
    let build = |build_dir, flags: &[&str]| {
        let mut flags = flags.to_vec();

        // Linux builds generally require -fPIC flag so ask CMake to add it.
        flags.push("-DCMAKE_POSITION_INDEPENDENT_CODE=1");

        env::set_current_dir(build_dir).expect("failed to cd to build directory");

        match build_with {
            BuildSystem::Ninja => {
                flags.push("-GNinja");
                run("cmake", &flags);
                run("ninja", &["crypto"]);
            }
            BuildSystem::Make => {
                run("cmake", &flags);
                run("make", &["crypto"]);
            }
        }
    };
    build(&abs_build_dir_1, &[&abs_boringssl_src]);

    //
    // After that we list all symbols present in the resulting static libraries and massage them.
    //

    let mut symbols = exported_symbols(&format!("{}/crypto/libcrypto.a", &abs_build_dir_1))
        .unwrap_or_else(|e| {
            panic!(
                "failed to read list of symbols exported by libcrypto: {}",
                e
            )
        });
    if symbols.is_empty() {
        panic!("no exported symbols found in libcrypto");
    }

    // Inlined functions from the compiler or runtime, should not be prefixed.
    let symbol_blacklist = [
        // Present in Windows builds.
        "__local_stdio_printf_options",
        "__local_stdio_scanf_options",
        "_vscprintf",
        "_vscprintf_l",
        "_vsscanf_l",
        "_xmm",
        "sscanf",
        "vsnprintf",
        // Present in Linux and macOS builds.
        "sdallocx",
    ];
    for blacklisted_symbol in &symbol_blacklist {
        symbols.remove(*blacklisted_symbol);
    }

    let mut symbols_file =
        fs::File::create(&abs_symbol_file).expect("could not create symbols file");
    for symbol in symbols {
        write!(symbols_file, "{}\n", symbol).expect("write to symbols file failed");
    }
    symbols_file
        .sync_all()
        .expect("failed to sync the symbols file to filesystem");

    //
    // Now we're ready for the second build telling CMake to rename symbols we're interested in.
    // After that we rename the produced library and pass linkage instructions via Cargo.
    //

    build(
        &abs_build_dir_2,
        &[
            &abs_boringssl_src,
            &cmake_version_flag,
            &cmake_symbol_listing,
        ],
    );

    // We symlink if possible to avoid rebuilding libcrypto.a and avoid copying it.
    #[cfg(unix)]
    let res = std::os::unix::fs::symlink(
        format!("{}/crypto/libcrypto.a", abs_build_dir_2),
        format!("{}/crypto/libsoter_crypto_{}.a", abs_build_dir_2, version_string),
    );
    #[cfg(windows)]
    let res = std::os::windows::fs::symlink_file(
        format!("{}/crypto/libcrypto.a", abs_build_dir_2),
        format!("{}/crypto/libsoter_crypto_{}.a", abs_build_dir_2, version_string),
    );
    #[cfg(not(any(unix, windows)))]
    let res = fs::rename(
        format!("{}/crypto/libcrypto.a", abs_build_dir_2),
        format!("{}/crypto/libsoter_crypto_{}.a", abs_build_dir_2, version_string),
    );
    if let Err(err) = res {
        // If the error is an AlreadyExists error, that just means we've already compiled before.
        if err.kind() != std::io::ErrorKind::AlreadyExists {
            panic!("could not symlink to libcrypto.a: {}", err)
        }
    }

    println!("cargo:rustc-link-search=native={}/crypto", abs_build_dir_2);
}

fn validate_dependencies() {
    let go = have_go();
    let cmake = have_cmake();
    let ninja = have_ninja();
    let make = have_make();

    if !go {
        panic!(
            "

Missing build dependency Go (1.11 or higher).

"
        );
    }
    if !cmake {
        panic!(
            "

Missing build dependency CMake.

"
        );
    }
    if cfg!(windows) && !ninja {
        panic!(
            "

Building on Windows requires the Ninja tool. See https://ninja-build.org/.

"
        );
    }
    if !make && !ninja {
        panic!(
            "

Building requires either Make or Ninja (https://ninja-build.org/).

"
        );
    }
}

fn have_go() -> bool {
    have("go", &["version"])
}

fn have_cmake() -> bool {
    have("cmake", &["--version"])
}

fn have_ninja() -> bool {
    have("ninja", &["--version"])
}

fn have_make() -> bool {
    have("make", &["--version"])
}

fn have(name: &str, args: &[&str]) -> bool {
    Command::new(name)
        .args(args)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn run(cmd: &str, args: &[&str]) {
    let output = Command::new(cmd)
        .args(args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .expect(&format!("failed to invoke {}", cmd));

    if !output.status.success() {
        panic!("{} failed with status {}", cmd, output.status);
    }
}

enum BuildSystem {
    Ninja,
    Make,
}

fn built_with(abs_dir: &str) -> Option<BuildSystem> {
    let is_file = |file| {
        fs::metadata(format!("{}/{}", abs_dir, file))
            .map(|meta| meta.is_file())
            .unwrap_or(false)
    };
    if is_file("build.ninja") {
        Some(BuildSystem::Ninja)
    } else if is_file("Makefile") {
        Some(BuildSystem::Make)
    } else {
        None
    }
}

fn exported_symbols(file: &str) -> Result<BTreeSet<String>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    fs::File::open(file)?.read_to_end(&mut bytes)?;
    binary_exported_symbols(&bytes)
}

fn binary_exported_symbols(bytes: &[u8]) -> Result<BTreeSet<String>, Box<dyn Error>> {
    let mut symbols = BTreeSet::new();
    match goblin::Object::parse(bytes)? {
        goblin::Object::Archive(archive) => {
            for (_member_name, member, _symbol_table) in archive.summarize() {
                // Member size is likely to be reported incorrectly by its header.
                assert!(
                    member.offset + (member.size() as u64) <= (bytes.len() as u64),
                    format!(
                        "archive member is outside of boundaries; offset: {}, size: {}",
                        member.offset,
                        member.size()
                    )
                );
                symbols.extend(binary_exported_symbols(
                    &bytes[member.offset as usize..member.offset as usize + member.size()],
                )?);
            }
        }
        goblin::Object::Elf(elf) => {
            for symbol in elf.syms.iter() {
                let name = elf
                    .strtab
                    .get(symbol.st_name)
                    .unwrap_or_else(|| {
                        panic!(
                            "incorrect symbol name table offset {} for: {:?}",
                            symbol.st_name, symbol
                        )
                    })
                    .expect("failed to read symbol name");
                if !name.is_empty()
                    && symbol.st_bind() != elf::sym::STB_LOCAL
                    && u32::try_from(symbol.st_shndx).unwrap() != elf::section_header::SHN_UNDEF
                {
                    symbols.insert(name.to_string());
                }
            }
        }
        goblin::Object::Mach(mach) => match mach {
            mach::Mach::Binary(obj) => {
                for symbol in obj.symbols() {
                    let (name, nlist) = symbol?;
                    if nlist.is_global() && !nlist.is_undefined() {
                        // Strip underscore symbol prefix.
                        symbols.insert(name[1..].to_string());
                    }
                }
            }
            mach::Mach::Fat(_obj) => panic!("unexpected multiarch Mach-O binary found in archive"),
        },
        // Symbols are stripped out of PE file.
        goblin::Object::PE(_pe) => panic!("unexpected PE executable found in archive"),
        // goblin::Object::parse doesn't detect COFF binaries.
        goblin::Object::Unknown(_magic) => {
            let coff = goblin::pe::Coff::parse(bytes)?;
            for (_size, _name, symbol) in coff.symbols.iter() {
                if symbol.section_number != goblin::pe::symbol::IMAGE_SYM_UNDEFINED
                    && symbol.storage_class == goblin::pe::symbol::IMAGE_SYM_CLASS_EXTERNAL
                {
                    // _name will only be populated for names no longer than 8 characters,
                    // otherwise string table lookup is necessary.
                    symbols.insert(symbol.name(&coff.strings)?.to_string());
                }
            }
        }
    };
    Ok(symbols)
}
