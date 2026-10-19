fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../proto/dbengine/v1/dbengine.proto");
    tonic_prost_build::configure()
        .build_client(false)
        .compile_protos(&["../proto/dbengine/v1/dbengine.proto"], &["../proto"])?;
    Ok(())
}
