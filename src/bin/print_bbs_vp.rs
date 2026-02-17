use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde_json::{Map, Value};
use zkryptium::bbsplus::ciphersuites::{BbsCiphersuite, Bls12381Sha256};
use zkryptium::keys::pair::KeyPair;
use zkryptium::schemes::algorithms::BBSplus;

use sd_benchmark::common_data::{CommonData, VC, CLAIMS};
use sd_benchmark::sd_algorithms::signatures::bbs_plus::BBSPlusInstance;

fn main() -> Result<(), String> {
    // 1. Parse the raw VC template
    let value_raw_vc: Value = serde_json::from_str::<Value>(VC)
        .map_err(|err| format!("Failed to parse raw VC: [{err}]"))?;
    let raw_vc: Map<String, Value> = serde_json::from_value(value_raw_vc)
        .map_err(|err| format!("Failed to convert raw VC: [{err}]"))?;

    // 2. Generate BBS+ issuer keypair
    let mut rng = StdRng::from_os_rng();
    let key_material: Vec<u8> = (0..Bls12381Sha256::IKM_LEN).map(|_| rng.random()).collect();
    let issuer_keypair = KeyPair::<BBSplus<Bls12381Sha256>>::generate(&key_material, None, None)
        .map_err(|err| format!("Error generating BBS+ keypair: [{err}]"))?;
    let issuer_pk = issuer_keypair.public_key();
    let issuer_sk = issuer_keypair.private_key();

    // 3. Load holder keys (ES256, used for proof of possession JWT wrapping)
    let (holder_public_key, holder_private_key) = CommonData::holder_keys()?;

    // 4. Print the original raw VC (input)
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║                    RAW VERIFIABLE CREDENTIAL                    ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    let raw_vc_json = serde_json::to_string_pretty(&Value::Object(raw_vc.clone()))
        .map_err(|e| format!("JSON error: [{e}]"))?;
    println!("{}\n", raw_vc_json);

    // 5. Issue a BBS+ VC
    let (vc, vc_jwt) = BBSPlusInstance::issue_vc(&raw_vc, issuer_pk, issuer_sk)?;

    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║               BBS+ VERIFIABLE CREDENTIAL (VC)                  ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    let vc_json = serde_json::to_string_pretty(&Value::Object(vc.clone()))
        .map_err(|e| format!("JSON error: [{e}]"))?;
    println!("{}\n", vc_json);

    println!("── VC JWT ({} bytes) ──", vc_jwt.len());
    println!("{}\n", vc_jwt);

    // 6. Verify the VC
    BBSPlusInstance::verify_vc(&vc, issuer_pk)?;
    println!("✓ VC verification passed\n");

    // 7. Select claims to disclose
    let disclosures: Vec<String> = vec!["name", "birthdate", "field"]
        .iter()
        .map(|x| x.to_string())
        .collect();

    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║           BBS+ VERIFIABLE PRESENTATION (VP)                    ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!("Disclosed claims: {:?}\n", disclosures);

    // 8. Issue a BBS+ VP (selective disclosure)
    let (vp, vp_jwt) = BBSPlusInstance::issue_vp(&vc, &disclosures, issuer_pk, &holder_private_key)?;

    let vp_json = serde_json::to_string_pretty(&Value::Object(vp.clone()))
        .map_err(|e| format!("JSON error: [{e}]"))?;
    println!("{}\n", vp_json);

    println!("── VP JWT ({} bytes) ──", vp_jwt.len());
    println!("{}\n", vp_jwt);

    // 9. Verify the VP
    BBSPlusInstance::verify_vp(&vp_jwt, issuer_pk, &holder_public_key)?;
    println!("✓ VP verification passed\n");

    // 10. Show the disclosed claims only
    if let Some(Value::Object(disclosed)) = vp.get(CLAIMS) {
        println!("── Disclosed claims in VP ──");
        for (key, value) in disclosed {
            println!("  {}: {}", key, value);
        }
    }

    Ok(())
}

// cargo run --bin print_bbs_vp -r
