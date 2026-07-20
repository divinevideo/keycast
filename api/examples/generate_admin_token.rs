use keycast_api::ucan_auth::{did_to_nostr_pubkey, nostr_pubkey_to_did, NostrKeyMaterial};
use nostr_sdk::Keys;
use serde_json::json;
use ucan::builder::UcanBuilder;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let server_nsec = std::env::var("SERVER_NSEC")?;
    let admin_did = std::env::var("ADMIN_DID")?;
    let tenant_id: i64 = std::env::var("TENANT_ID")?.parse()?;

    let server_keys = Keys::parse(&server_nsec)?;
    let admin_pubkey = did_to_nostr_pubkey(&admin_did)?;
    let server_key_material = NostrKeyMaterial::from_keys(server_keys);

    let facts = json!({
        "tenant_id": tenant_id,
        "redirect_origin": "admin",
        "admin": true,
        "admin_role": "full",
    });

    let ucan = UcanBuilder::default()
        .issued_by(&server_key_material)
        .for_audience(&nostr_pubkey_to_did(&admin_pubkey))
        .with_lifetime(30 * 24 * 3600)
        .with_fact(facts)
        .build()?
        .sign()
        .await?;

    println!("{}", ucan.encode()?);
    Ok(())
}
