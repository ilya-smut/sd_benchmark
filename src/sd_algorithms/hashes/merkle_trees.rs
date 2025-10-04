use josekit::jws::{ES256, JwsVerifier};
use rs_merkle::{Hasher, MerkleProof, MerkleTree};
use rs_merkle::algorithms::Sha256;
use serde_json::{Map, Value};
use crate::sd_algorithms::hashes::hash_sd_algorithm::HashSdAlgorithm;
use crate::sd_algorithms::sd_algorithm::SdAlgorithm;

/// Identifier for the root of the merkle tree as a field of the VC/VP.
const ROOT: &str = "root";
/// Identifier for the salts used for each claim in the Merkle Tree
const SALTS: &str = "salts";
/// Identifier for the merkle tree proof field in the VC/VP.
const MERKLE_PROOF: &str = "merkle_proof";
/// Identifier for leaves' length in the merkle tree.
const LEN: &str = "leaves_len";
/// Identifier for the signature of the merkle tree's root.
const ROOT_SIGNATURE: &str = "root_sig";
/// Identifier for the element containing the disclosed indices used to compute the merkle proof.
const DISCLOSED_INDICES: &str = "disclosed_indices";
/// Length of hashes in bytes.
const HASH_LEN: usize = 32;


/// Struct to contain an instance of the Merkle Tree algorithm for selective disclosure.
pub struct MerkleTreeInstance;

impl SdAlgorithm for MerkleTreeInstance {
    const ALGORITHM: &'static str = "MERKLE";
}

impl HashSdAlgorithm for MerkleTreeInstance {}

impl MerkleTreeInstance {

    /// A simple function to map key-value pairs to a string before passing it to a SHA256 hashing algorithm instance.
    ///
    /// # Arguments
    /// * `key` - Name of the element.
    /// * `value` - Value of the element.
    ///
    /// # Returns
    /// Returns the hash of the concatenation of key-value.
    fn map_key_value_to_sha256(key: String, value: String) -> [u8; HASH_LEN] {
        let mut result = key.clone();
        result.push(':');
        result.push_str(value.as_str());

        Sha256::hash(result.as_bytes())
    }


    /// Function to map claims to merkle tree leaves by hashing them.
    ///
    /// # Arguments
    /// * `claims` - Key-Value map of the claims to be converted.
    /// * `salts` - Key-Value map of the salts to be used in hashing.
    ///
    /// # Returns
    /// A vector containing the hashes of the leaves encoded as byte arrays.
    fn convert_claims_and_salts_to_leaves(claims: &Map<String, Value>, salts: &Map<String, Value>) -> Result<Vec<[u8; HASH_LEN]>, String> {
        let mut leaves = vec![];

        for (key, claim) in claims {
            let claim = match claim {
                Value::String(claim) => claim.clone(),
                _ => return Err(format!("Claim in key {} is not a string", key))
            };

            let salt_value = match salts.get(key) {
                Some(salt) => salt.clone(),
                _ => return Err(format!("Salt {} not found in claims", key))
            };

            let salt = match salt_value {
                Value::String(salt) => salt.clone(),
                _ => return Err(format!("Salt {} is not a string", key))
            };

            claim.clone().push_str(salt.as_str());
            leaves.push(Self::map_key_value_to_sha256(key.clone(), claim));
        }

        Ok(leaves)
    }

    /// Filters the VC or VP passed as input to only include the salts corresponding to the
    /// disclosed claims present in the disclosure vector.
    ///
    /// # Arguments
    /// * `map` - VC from which it's necessary to filter the salts.
    /// * `disclosures` - A vector of strings that contains the disclosures to be inserted in the VP.
    ///
    /// # Returns
    /// Returns a result containing an array of disclosed indices or a string representing an error.
    fn filter_salts_by_disclosure_and_insert(map: &mut Map<String, Value>, disclosures: &Vec<String>) -> Result<(), String> {

        let salts: &Map<String, Value> = &Self::get_and_decode(map, SALTS.to_string())?;
        let mut disclosed_salts: Map<String, Value> = Map::new();
        let mut disclosed_indices: Vec<usize> = vec![];

        'disclosure_loop: for disclosure in disclosures {
            for (i, (key, value)) in salts.iter().enumerate() {
                if *key == *disclosure {
                    disclosed_salts.insert(key.clone(), value.clone());
                    disclosed_indices.push(i);
                    continue 'disclosure_loop;
                }
            }
        }

        Self::serialize_and_insert(map, SALTS.to_string(), &disclosed_salts)?;

        Ok(())

    }

    /// High level function for the verification of the merkle tree root signature.
    ///
    /// # Arguments
    /// * `map` - Key-Value map of either the VC or the VP containing the root and its signature.
    /// * `issuer_public_key` - Issuer's public key to verify the signature with.
    ///
    /// # Returns
    /// Returns a result containing the verified root of the merkle tree.
    fn verify_root_signature(map: &Map<String, Value>, issuer_public_key: &impl AsRef<[u8]>) -> Result<Vec<u8>, String> {
        let serialized_merkle_root: [u8; HASH_LEN] = Self::get_and_decode(map, ROOT.to_string())?;
        let root_signature: Vec<u8> = Self::get_and_decode(map, ROOT_SIGNATURE.to_string())?;

        let verifier = match ES256.verifier_from_pem(issuer_public_key) {
            Ok(verifier) => { verifier }
            Err(err) => { return Err(format!("Could not create verifier from pem: [{err}]")); }
        };

        match verifier.verify(&serialized_merkle_root, root_signature.as_slice()) {
            Ok(_) => { Ok(serialized_merkle_root.to_vec()) }
            Err(err) => { Err(format!("Failed verification of merkle root signature: [{err}]")) }
        }
    }


    /// From a set of leaves construct a merkle tree and derive the merkle root
    ///
    /// # Arguments
    /// * `leaves` - Set of leaves from which the tree needs to be constructed.
    ///
    /// # Returns
    /// Returns the root of the merkle tree.
    fn derive_root_from_leaves(leaves: &Vec<[u8; HASH_LEN]>) -> Result<[u8; HASH_LEN], String> {
        let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        match merkle_tree.root() {
            None => { Err("Could not retrieve root of Merkle Trees".to_string()) }
            Some(root) => { Ok(root) }
        }
    }


    /// Given a raw VC containing a few fields and the credentialSubject field to include claims, create all the necessary data to create a VC using this algorithm.
    ///
    /// # Arguments
    /// * `raw_vc` - Template VC containing a credential.
    /// * `issuer_private_key` - Private key of the issuer used to generate the signature of the list of hashes.
    ///
    /// # Returns
    /// Returns a VC both in the form of a Map and in the form of an unsigned JWT.
    pub fn issue_vc(raw_vc: &Map<String, Value>, issuer_private_key: &impl AsRef<[u8]>) -> Result<(Map<String, Value>, String), String> {

        let mut vc = raw_vc.clone();

        let claims: &Map<String, Value> = Self::extract_claims(&vc)?;
        let salts: &Map<String, Value> = &claims.into_iter().map(|(key, _)|{
            (key.clone(), Value::String(Self::generate_random_salt()))
        }).collect();
        let leaves = Self::convert_claims_and_salts_to_leaves(claims, salts)?;

        let merkle_root: [u8; HASH_LEN] = Self::derive_root_from_leaves(&leaves)?;

        Self::serialize_and_insert(&mut vc, ROOT.to_string(), &merkle_root)?;
        Self::serialize_and_insert(&mut vc, LEN.to_string(), &leaves.len())?;
        Self::serialize_and_insert(&mut vc, SALTS.to_string(), &salts)?;

        let signer = match ES256.signer_from_pem(issuer_private_key) {
            Ok(signer) => { signer }
            Err(err) => { return Err(format!("Failed to create signer: [{err}]"));}
        };

        let signature: Vec<u8> = match signer.sign(merkle_root.as_slice()) {
            Ok(signature) => { signature }
            Err(err) => { return Err(format!("Failed to sign message: [{err}]")) }
        };

        Self::serialize_and_insert(&mut vc, ROOT_SIGNATURE.to_string(), &signature)?;
        let json_credential = Self::encode_jwt(&vc)?;

        Ok((vc, json_credential))
    }


    /// Given a VC, verify it using all the necessary data.
    ///
    /// # Arguments
    /// * `vc` - Verifiable Credential.
    /// * `issuer_public_key` - Issuer's public key to verify the signature of the merkle tree.
    ///
    /// # Returns
    /// Returns a string containing an error in case of failure.
    pub fn verify_vc(vc: &Map<String, Value>, issuer_public_key: &impl AsRef<[u8]>) -> Result<(), String> {

        let claims: &Map<String, Value> = Self::extract_claims(vc)?;
        let salts: &Map<String, Value> = &Self::get_and_decode(vc, SALTS.to_string())?;
        let leaves: Vec<[u8; HASH_LEN]> = Self::convert_claims_and_salts_to_leaves(claims, salts)?;
        let computed_root: [u8; HASH_LEN] = Self::derive_root_from_leaves(&leaves)?;
        let vc_root: [u8; HASH_LEN] = Self::derive_root_from_leaves(&leaves)?;

        if computed_root != vc_root {
            return Err(format!("Root in vc and root computed do not match {:?} - {:?}", computed_root, vc_root))
        }

        Self::verify_root_signature(&vc, issuer_public_key)?;

        Ok(())
    }


    /// Given a VC, and a set of disclosures, create a Verifiable Presentation accordingly.
    ///
    /// # Arguments
    /// * `vc` - Verifiable Credential.
    /// * `disclosures` - List of strings containing the names of the claims that are to be disclosed.
    /// * `holder_private_key` - Holder's private key necessary for proof of possession.
    ///
    /// # Returns
    /// Returns the VP both in form of a Map and in form of a signed JWT.
    pub fn issue_vp(vc: &Map<String, Value>, disclosures: &Vec<String>, holder_private_key: &impl AsRef<[u8]>) -> Result<(Map<String, Value>, String), String> {

        let mut vp: Map<String, Value> = vc.clone();
        let claims: &Map<String, Value> = Self::extract_claims(vc)?;
        let salts: &Map<String, Value> = &Self::get_and_decode(vc, SALTS.to_string())?;
        let leaves: Vec<[u8; HASH_LEN]> = Self::convert_claims_and_salts_to_leaves(claims, salts)?;
        let merkle_tree: MerkleTree<Sha256> = MerkleTree::from_leaves(leaves.as_slice());

        Self::filter_salts_by_disclosure_and_insert(&mut vp, disclosures)?;
        let disclosed_indices = Self::filter_claims_by_disclosure_and_insert(&mut vp, disclosures)?;

        let merkle_proof: MerkleProof<Sha256> = merkle_tree.proof(&disclosed_indices);
        let proof_bytes = merkle_proof.to_bytes();

        Self::serialize_and_insert(&mut vp, MERKLE_PROOF.to_string(), &proof_bytes)?;
        Self::serialize_and_insert(&mut vp, DISCLOSED_INDICES.to_string(), &disclosed_indices)?;
        let jwt = Self::encode_and_sign_jwt(&mut vp, &holder_private_key)?;

        Ok((vp, jwt))
    }


    /// Given a VP, verify it using all the necessary data.
    ///
    /// # Arguments
    /// * `jwt` - Verifiable Presentation encoded as a jwt.
    /// * `issuer_public_key` - Issuer's public key to verify the signature of the merkle tree.
    /// * `holder_public_key` - Holder's public key to verify the proof of possession.
    ///
    /// # Returns
    /// Returns a string containing an error in case of failure.
    pub fn verify_vp(jwt: &String, issuer_public_key: &impl AsRef<[u8]>, holder_public_key: &impl AsRef<[u8]>) -> Result<(), String> {

        let vp = Self::decode_and_verify_jwt(&jwt, &holder_public_key)?;
        let disclosed_claims = Self::extract_claims(&vp)?;
        let disclosed_salts = &Self::get_and_decode(&vp, SALTS.to_string())?;

        let proof_bytes: Vec<u8> = Self::get_and_decode(&vp, MERKLE_PROOF.to_string())?;
        let proof: MerkleProof<Sha256> = match MerkleProof::from_bytes(proof_bytes.as_slice()) {
            Ok(proof) => { proof }
            Err(err) => { return Err(format!("Could not decode proof from bytes: [{err}]")) }
        };

        let disclosed_indices: Vec<usize> = Self::get_and_decode(&vp, DISCLOSED_INDICES.to_string())?;
        let leaves_len: usize = Self::get_and_decode(&vp, LEN.to_string())?;
        let disclosed_leaves = Self::convert_claims_and_salts_to_leaves(&disclosed_claims, &disclosed_salts)?;
        let merkle_root_vec: Vec<u8> = Self::verify_root_signature(&vp, issuer_public_key)?;
        let mut merkle_root: [u8; HASH_LEN] = [0u8; HASH_LEN];

        if merkle_root_vec.len() != HASH_LEN {
            return Err(format!("Merkle root array length is not {HASH_LEN}"));
        } else {
            for (i, byte) in merkle_root_vec.iter().enumerate() {
                merkle_root[i] = byte.clone();
            }
        }

        if proof.verify(merkle_root, disclosed_indices.as_slice(), disclosed_leaves.as_slice(), leaves_len) {
            Ok(())
        } else {
            Err("Proof verification failed.".to_string())
        }

    }
}


#[cfg(test)]
mod tests {
    use serde_json::{Map, Value};

    use crate::common_data::{CommonData, VC};

    use super::*;

    #[test]
    fn merkle() -> Result<(), String> {

        let value_raw_vc: Value = match serde_json::from_str::<Value>(VC) {
            Ok(value_vc) => { value_vc }
            Err(err) => { return Err(format!("[Merkle] Failed to parse Raw Verifiable Credential from string. [{err}]")); }
        };

        let mut raw_vc: Map<String, Value> = match serde_json::from_value::<Map<String, Value>>(value_raw_vc) {
            Ok(vc) => { vc }
            Err(err) => { return Err(format!("[Merkle] Failed to parse Raw Verifiable Credential from Value. [{err}]")); }
        };

        let (holder_public_key, holder_private_key) = CommonData::holder_keys()?;
        let (issuer_public_key, issuer_private_key) = CommonData::issuer_keys()?;

        let (vc, _jwt) = match MerkleTreeInstance::issue_vc(&mut raw_vc, &issuer_private_key) {
            Ok(result) => { result }
            Err(err) => { return Err(format!("[Merkle] Failed to issue vc [{err}]."))}
        };

        match MerkleTreeInstance::verify_vc(&vc, &issuer_public_key) {
            Ok(_) => { println!("[Merkle] Successfully verified vc.")}
            Err(err) => { return Err(format!("[Merkle] Failed to verify vc [{err}]."))}
        };

        let disclosures = vec!["name", "birthdate"].iter().map(|x| x.to_string()).collect();
        let (_vp, vp_jwt) = match MerkleTreeInstance::issue_vp(&vc, &disclosures, &holder_private_key) {
            Ok(result) => { result }
            Err(err) => { return Err(format!("[Merkle] Failed to issue verifiable presentation: [{err}].")) }
        };

        match MerkleTreeInstance::verify_vp(&vp_jwt, &issuer_public_key, &holder_public_key) {
            Ok(_) => { println!("[Merkle] Successfully verified vp.")}
            Err(err) => { return Err(format!("[Merkle] Failed to verify vp [{err}].")) }
        };

        Ok(())
    }
}