use std::env;
use std::path::PathBuf;
use std::process::Command;

fn checked(program: &str, args: &[&str]) -> String {
    let result = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to execute {program}: {error}"));
    if !result.status.success() {
        panic!(
            "{program} failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    String::from_utf8(result.stdout).expect("native build tool emitted invalid UTF-8")
}

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_LINUX_QT_CONSENT");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_LINUX_KWALLET_GPG");
    if env::var_os("CARGO_FEATURE_LINUX_QT_CONSENT").is_none()
        || env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux")
    {
        return;
    }

    let project_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../..");
    let qt_source = project_root.join("apps/linux/receiver/ui");
    let output = PathBuf::from(env::var("OUT_DIR").unwrap()).join("qt-owner-prompt");
    println!(
        "cargo:rerun-if-changed={}",
        qt_source.join("CMakeLists.txt").display()
    );
    for name in [
        "IncomingOfferDialog.hpp",
        "IncomingOfferDialog.cpp",
        "QtConsentBridge.cpp",
        "KWalletGpg.cpp",
    ] {
        println!("cargo:rerun-if-changed={}", qt_source.join(name).display());
    }
    let source = qt_source.to_str().expect("Qt source path must be UTF-8");
    let build = output.to_str().expect("Qt build path must be UTF-8");
    let kwallet_enabled = env::var_os("CARGO_FEATURE_LINUX_KWALLET_GPG").is_some();
    checked(
        "cmake",
        &[
            "-S",
            source,
            "-B",
            build,
            "-DCMAKE_BUILD_TYPE=Release",
            if kwallet_enabled {
                "-DOPENDROP_KWALLET_GPG=ON"
            } else {
                "-DOPENDROP_KWALLET_GPG=OFF"
            },
        ],
    );
    checked(
        "cmake",
        &[
            "--build",
            build,
            "--target",
            "opendrop-linux-owner-prompt",
            "--parallel",
            "2",
        ],
    );
    println!("cargo:rustc-link-search=native={build}");
    println!("cargo:rustc-link-lib=static=opendrop-linux-owner-prompt");

    // CMake uses Qt6Widgets and libsystemd. Link the exact libraries found
    // by the runner's pkg-config, not guessed absolute host library paths.
    let flags = if kwallet_enabled {
        checked(
            "pkg-config",
            &["--libs", "Qt6Widgets", "Qt6DBus", "libsystemd"],
        )
    } else {
        checked("pkg-config", &["--libs", "Qt6Widgets", "libsystemd"])
    };
    for flag in flags.split_whitespace() {
        if let Some(library) = flag.strip_prefix("-l") {
            println!("cargo:rustc-link-lib={library}");
        } else if let Some(path) = flag.strip_prefix("-L") {
            println!("cargo:rustc-link-search=native={path}");
        } else if flag != "-pthread" {
            panic!("unreviewed Qt/systemd linker argument: {flag}");
        }
    }
    if kwallet_enabled {
        // The CMake KF6::Wallet imported target resolves libKF6Wallet.so.
        // No Secret Service or wallet backend is linked in the default
        // PKCS11-only executable.
        println!("cargo:rustc-link-lib=KF6Wallet");
    }
    println!("cargo:rustc-link-lib=stdc++");
}
