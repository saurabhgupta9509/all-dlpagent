use std::env;
use std::path::PathBuf;

fn main() {
    // Set linker arguments for a kernel driver
    println!("cargo:rustc-link-arg=/DRIVER");
    println!("cargo:rustc-link-arg=/SUBSYSTEM:NATIVE");
    println!("cargo:rustc-link-arg=/NODEFAULTLIB");
    println!("cargo:rustc-link-arg=/ENTRY:DriverEntry");
    println!("cargo:rustc-link-arg=/DYNAMICBASE");
    println!("cargo:rustc-link-arg=/NXCOMPAT");

    // Tell cargo to link against the filter driver library
    println!("cargo:rustc-link-lib=FltMgr");

    // Tell cargo where to find the fsfilter .lib file
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let target_dir = manifest_dir.join("target").join(env::var("PROFILE").unwrap());
    println!("cargo:rustc-link-search=native={}", target_dir.display());
}