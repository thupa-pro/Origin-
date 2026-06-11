use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn hash_hex(data: &[u8]) -> String {
    origin_core::hash::hash_hex(data)
}

#[wasm_bindgen]
pub fn verify_consistency(statement: &[u8], artifact: &[u8]) -> String {
    match origin_core::verify_consistency(statement, artifact) {
        Ok(()) => "VERIFIED".into(),
        Err(e) => format!("FAILED: {}", e),
    }
}

#[wasm_bindgen]
pub fn parse_audit(statement: &[u8]) -> String {
    match origin_core::Statement::parse(statement) {
        Ok(stmt) => origin_core::audit::audit(&stmt),
        Err(e) => format!("Parse error: {}", e),
    }
}
