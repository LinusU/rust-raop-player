fn main() {
    println!("cargo:rustc-link-lib=static=raop");
    println!("cargo:rustc-link-search=native=../build-host");
    println!("cargo:rustc-flags=-l dylib=c++");
}
