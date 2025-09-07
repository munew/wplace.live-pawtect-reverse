use std::error::Error;
use sha2::{Digest, Sha256};

pub fn sha256(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>>  {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    
    Ok(hash.to_vec())
}