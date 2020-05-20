extern crate bindgen;
extern crate cbindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    // Tell cargo to tell rustc to link the system olm
    // shared library.
    println!("cargo:rustc-link-lib=olm");
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
