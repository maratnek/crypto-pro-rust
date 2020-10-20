extern crate bindgen;

use std::env;
use std::path::PathBuf;

// make[1]: Entering directory '/home/maratworker/Projects/CryptoPro/src2/doxygen/CSP/CreatingHash'
// gcc -DUNIX -DHAVE_LIMITS_H  -D_COMPACT -DHAVE_STDINT_H  -I/opt/cprocsp/include -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/asn1c/rtsrc -I/opt/cprocsp/include/asn1data -DSIZEOF_VOID_P=8 -g   -c -o CreatingHash.o CreatingHash.c
// g++ -std=c++98 -D_GLIBCXX_USE_CXX11_ABI=0 CreatingHash.o   -L/opt/cprocsp/lib/amd64 -lssp -lcapi10 -lcapi20 -lrdrsup -lpthread  -g  -o CreatingHash 
// make[1]: Leaving directory '/home/maratworker/Projects/CryptoPro/src2/doxygen/CSP/CreatingHash'
fn main(){
    // let dst = Config::new("libbadmath").build();
    let includedir = "/opt/cprocsp/include/cpcsp";
    let link_search_path = "/opt/cprocsp/lib/amd64";

    println!("cargo:rustc-link-search=native={}", link_search_path);
    // println!("cargo:rustc-link-lib=dylib=badmath");
    println!("cargo:include={}", includedir);

    // Tell cargo to tell rustc to link the system bzip2
    // shared library.
    // println!("cargo:rustc-link-lib=badmath");

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
// -DUNIX -DHAVE_LIMITS_H  -D_COMPACT -DHAVE_STDINT_H 
    let var_clang_arg1 = [
        "-DSIZEOF_VOID_P=8".to_string(),
        "-DUNIX".to_string(),
        "-DHAVE_LIMITS_H".to_string(),
        "-D_COMPACT".to_string(), 
        "-DHAVE_STDINT_H".to_string(), 
        format!("-I{}", includedir) 
    ];
    let bindings = bindgen::Builder::default()
        .clang_args(var_clang_arg1.iter())
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        // .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}