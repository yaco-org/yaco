//! Prints the OpenAPI spec of the node API as JSON.

use utoipa::OpenApi;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", yaco_api::ApiDoc::openapi().to_pretty_json()?);
    Ok(())
}
