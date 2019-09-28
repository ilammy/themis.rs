// Copyright 2018 Google LLC
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

//! Build BoringSSL static library with properly renamed symbols.

use std::env;
use std::fs;
use std::process::{Command, Stdio};

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
    // After that we list all symbols present in the resulting static libraries and run the build
    // again with enabled prefixes.
    //

    env::set_current_dir(&abs_boringssl_src).expect("failed to cd to BoringSSL directory");

    run(
        "go",
        &[
            "run",
            "util/read_symbols.go",
            "-out",
            &abs_symbol_file,
            &format!("{}/crypto/{}", &abs_build_dir_1, lib("crypto")),
        ],
    );

    build(
        &abs_build_dir_2,
        &[
            &abs_boringssl_src,
            &cmake_version_flag,
            &cmake_symbol_listing,
        ],
    );

    //
    // After that we rename the produced library and pass linkage instructions via Cargo.
    // We symlink if possible to avoid rebuilding libcrypto.a and avoid copying it.
    //

    let crypto = format!("{}/crypto/{}", &abs_build_dir_2, lib("crypto"));
    let soter_crypto = format!("soter_crypto_{}", version_string);
    let soter_crypto = format!("{}/crypto/{}", &abs_build_dir_2, lib(&soter_crypto));

    if let Err(err) = symlink_from_to(&crypto, &soter_crypto) {
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

fn symlink_from_to(from: &str, to: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    return std::os::unix::fs::symlink(from, to);
    #[cfg(windows)]
    return std::os::windows::fs::symlink_file(from, to);
    #[cfg(not(any(unix, windows)))]
    return fs::rename(from, to);
}

fn lib(name: &str) -> String {
    // TODO: ensure that we support both *-pc-windows-msvc and *-pc-windows-gnu
    if cfg!(windows) {
        format!("{}.lib", name)
    } else {
        format!("lib{}.a", name)
    }
}
