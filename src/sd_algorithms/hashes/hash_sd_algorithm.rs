use josekit::jws::ES256;
use rand::Rng;

/// Trait that implements several methods shared across different algorithm instances.
pub trait HashSdAlgorithm {

    /// Salt dimension in bytes.
    const SALT_DIMENSION: usize = 16;   // 16 u8 = 16 * 8 = 128 bits

    /// A function to randomly generate salts.
    ///
    /// # Returns
    /// The vector of salts created.
    fn generate_random_salt() -> String {
        let mut bytes = vec![0; Self::SALT_DIMENSION];
        let mut rng = rand::rng();

        rng.fill(&mut bytes[..]);
        multibase::Base::Base64Url.encode(bytes)
    }

    /// Given an array of bytes to be signed, and a private key, returns a ES256 signature.
    ///
    /// # Arguments
    /// * `bytes` - Bytes to be digitally signed.
    /// * `private_key` - Private key to be used to derive the signature.
    ///
    /// # Returns
    /// Returns a vector of bytes containing the signature nested in a result, or a string containing an error in case of failure.
    fn derive_signature(bytes: &[u8], private_key: &impl AsRef<[u8]>) -> Result<Vec<u8>, String> {
        let signer = match ES256.signer_from_pem(private_key) {
            Ok(signer) => { signer }
            Err(err) => { return Err(format!("Failed to create signer: [{err}]")); }
        };

        match signer.sign(bytes) {
            Ok(signature) => { Ok(signature) }
            Err(_) => {  Err("Failed to sign message".to_string()) }
        }
    }

    /// Verifies a previously generated signature on the byte vector passed in input.
    ///
    /// # Arguments
    /// * `bytes` - Byte vector on which the signature was created.
    /// * `signature` - Byte vector containing the signature to be verified.
    /// * `public_key` - Byte vector containing the public key to verify the signature with.
    ///
    /// # Returns
    /// Returns a string containing an error in case of failure.
    fn verify_signature(bytes: &[u8], signature: &Vec<u8>, public_key: &impl AsRef<[u8]>) -> Result<(), String> {
        let verifier = match ES256.verifier_from_pem(public_key) {
            Ok(verifier)  => { verifier }
            Err(err) => { return Err(format!("Failed to create verifier: {err}")); }
        };
        match verifier.verify(bytes, &signature) {
            Ok(_) => { Ok(()) }
            Err(err) => { Err(format!("Error in verification: {}", err.to_string())) }
        }
    }
}