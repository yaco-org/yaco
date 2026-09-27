//! Prints the OpenAPI spec of the node API as JSON.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", yaco_agent::api::spec().to_pretty_json()?);
    Ok(())
}
