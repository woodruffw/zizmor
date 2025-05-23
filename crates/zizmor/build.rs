use std::fs::{self, File};
use std::path::Path;
use std::{env, io};

use fst::MapBuilder;

fn do_context_capabilities() {
    println!("cargo::rerun-if-changed=../../support/context-capabilities.csv");

    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir).join("context-capabilities.fst");

    let out = io::BufWriter::new(File::create(out_path).unwrap());
    let mut build = MapBuilder::new(out).unwrap();

    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_path("../../support/context-capabilities.csv")
        .unwrap();

    for record in rdr.records() {
        let record = record.unwrap();
        let context = record.get(0).unwrap();
        let capability = match record.get(1).unwrap() {
            "arbitrary" => 0,
            "structured" => 1,
            "fixed" => 2,
            _ => panic!("Unknown capability"),
        };

        build.insert(context, capability).unwrap();
    }

    build.finish().unwrap();
}

fn do_codeql_injection_sinks() {
    let source = "../../support/codeql-injection-sinks.json";
    let target = Path::new(&env::var("OUT_DIR").unwrap()).join("codeql-injection-sinks.json");

    print!("cargo::rerun-if-changed={}", source);

    fs::copy(source, target).unwrap();
}

fn main() {
    do_context_capabilities();
    do_codeql_injection_sinks();
}
