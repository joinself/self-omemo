extern crate bindgen;
extern crate cbindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    // Tell cargo to tell rustc to link the system olm
    // shared library.

    let target = env::var("TARGET").unwrap();

    if target == "" {
        println!("cargo:rustc-link-search=/usr/lib");
    } else if target == "aarch64-linux-android" {
        println!("cargo:rustc-link-search=/usr/local/lib/arm64-v8a");
    } else if target == "armv7-linux-androideabi" {
        println!("cargo:rustc-link-search=/usr/local/lib/armeabi-v7a");
    } else if target == "i686-linux-android" {
        println!("cargo:rustc-link-search=/usr/local/lib/x86");
    } else if target == "x86_64-linux-android" {
        println!("cargo:rustc-link-search=/usr/local/lib/x86_64");
    }

    println!("cargo:rustc-link-lib=self_olm");
    println!("cargo:rustc-link-lib=sodium");

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=olm.h");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("olm.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("olm.rs"))
        .expect("Couldn't write bindings!");

    // generate c header bindings
    // NOTE: if it fails to update the header file, comment this out,
    // run cargo build, then uncomment and run cargo build again.
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    cbindgen::Builder::new()
      .with_crate(crate_dir)
      .with_config(cbindgen::Config::from_file("cbindgen.toml").unwrap())
      .generate()
      .expect("Unable to generate bindings")
      .write_to_file("self_omemo.h");
}
