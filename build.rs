use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

fn main() {
    hello();
}

fn hello() {
    SkeletonBuilder::new()
        .source(PathBuf::new().join("src").join("bpf").join("simple.bpf.c"))
        .build_and_generate("simple")
        .unwrap();
}
