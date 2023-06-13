// Copyright 2020 Self Group Ltd. All Rights Reserved.

extern crate cbindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

      cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_language(cbindgen::Language::C)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("self_omemo.h");


      let include_dir = crate_dir.clone();

      let mut shared_object_dir = PathBuf::from(crate_dir);
  
      shared_object_dir.push("target");
      shared_object_dir.push(env::var("PROFILE").unwrap());
  
      let shared_object_dir = shared_object_dir.as_path().to_string_lossy();
  
      println!(
          "cargo:rustc-env=INLINE_C_RS_CFLAGS=-I{I} -L{L} -D_DEBUG -D_CRT_SECURE_NO_WARNINGS",
          I = include_dir,
          L = shared_object_dir,
      );
  
      println!(
          "cargo:rustc-env=INLINE_C_RS_LDFLAGS={shared_object_dir}/libself_omemo.so",
          shared_object_dir = shared_object_dir,
      );
}
