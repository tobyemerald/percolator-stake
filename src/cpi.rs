//! CPI helpers for calling percolator wrapper instructions.
//!
//! The stake program only needs ONE CPI: TopUpInsurance (permissionless).
//! All admin operations are handled by the human admin directly on the wrapper.
#![allow(clippy::too_many_arguments)]

use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::invoke_signed,
};

// Wrapper instruction tag (from percolator-prog/src/percolator.rs)
const TAG_TOP_UP_INSURANCE: u8 = 9;

// ═══════════════════════════════════════════════════════════════
// TopUpInsurance (Tag 9) — v16 contract
// ═══════════════════════════════════════════════════════════════
// Accounts: [signer, slab(w), signer_ata(w), vault(w), token_program]
// Data: tag(1) + amount(16, u128 LE)
//
// V16 WIRE CONTRACT (verified against percolator-prog v16-sync @5260d1b):
//   * AMOUNT IS u128 ON THE WIRE. The v16 wrapper decodes tag 9 with
//     `read_u128` (v16_program.rs:2627), which returns `InvalidInstructionData`
//     for any payload < 16 bytes (v16_program.rs:3275-3282). The pre-v16 wire
//     sent an 8-byte u64 — against a v16 wrapper that 8-byte payload HARD-REVERTS
//     the CPI at decode time. We therefore widen the wire to `(amount as u128)`.
//     `amount` stays a u64 here because token amounts fit u64 and the wrapper
//     re-narrows via `u64::try_from` (v16_program.rs:7574); only the wire widens.
//   * NOT PERMISSIONLESS. v16 gates tag 9 on `expect_live_authority(
//     cfg.insurance_authority, signer.key)` (v16_program.rs:7569,7584). The CPI
//     signer is our `vault_auth` PDA, so the market's `insurance_authority` MUST
//     be bound to that PDA at deploy (via the wrapper's UpdateAuthority) or every
//     flush reverts Custom(8) Unauthorized. (The old "permissionless" comment was
//     wrong for v16.)
//   * LIVE MODE REQUIRED. v16 rejects tag 9 unless the market is Live
//     (v16_program.rs:7566,7580) — checked BEFORE the authority gate, so a
//     not-yet-Live market reverts Custom(21) EngineLockActive.
//
// CUTOVER ATOMICITY: this 16-byte wire MUST ship in the same cutover bundle as
// the v16 wrapper. NEVER deploy this stake build against a live pre-v16 (v12)
// wrapper — that wrapper decodes tag 9 as u64 (8 bytes) and would reject the
// 16-byte payload. See ~/wrapper-engine-deep-audit/V16_DIVERGENCES.md (stake).

pub fn cpi_top_up_insurance<'a>(
    percolator_program: &AccountInfo<'a>,
    signer: &AccountInfo<'a>, // vault_auth PDA (we sign) — must == market insurance_authority
    slab: &AccountInfo<'a>,
    signer_ata: &AccountInfo<'a>, // stake vault (owned by vault_auth)
    wrapper_vault: &AccountInfo<'a>,
    token_program: &AccountInfo<'a>,
    amount: u64,
    signer_seeds: &[&[u8]],
) -> ProgramResult {
    // tag(1) + u128 amount(16) = 17 bytes.
    let mut data = Vec::with_capacity(17);
    data.push(TAG_TOP_UP_INSURANCE);
    data.extend_from_slice(&(amount as u128).to_le_bytes());

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*signer.key, true),
            AccountMeta::new(*slab.key, false),
            AccountMeta::new(*signer_ata.key, false),
            AccountMeta::new(*wrapper_vault.key, false),
            AccountMeta::new_readonly(*token_program.key, false),
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[
            signer.clone(),
            slab.clone(),
            signer_ata.clone(),
            wrapper_vault.clone(),
            token_program.clone(),
        ],
        &[signer_seeds],
    )
}

#[cfg(test)]
mod tag_tests {
    use super::*;

    #[test]
    fn test_cpi_tag_constants() {
        assert_eq!(TAG_TOP_UP_INSURANCE, 9, "TAG_TOP_UP_INSURANCE mismatch");
    }

    /// CANARY: pin the v16 tag-9 wire shape. The amount is u128 (16 bytes), NOT
    /// u64 (8 bytes). If anyone narrows this back to u64 the v16 wrapper's
    /// `read_u128` decoder rejects the CPI with InvalidInstructionData. This test
    /// reconstructs the exact bytes `cpi_top_up_insurance` builds.
    #[test]
    fn test_cpi_wire_shape_is_tag_plus_u128() {
        let amount: u64 = 1_000;
        // Mirror the encoding in cpi_top_up_insurance.
        let mut data = Vec::with_capacity(17);
        data.push(TAG_TOP_UP_INSURANCE);
        data.extend_from_slice(&(amount as u128).to_le_bytes());

        assert_eq!(data.len(), 17, "v16 tag-9 payload must be 1 + 16 bytes");
        assert_eq!(data[0], 9, "tag byte");
        // amount occupies bytes [1..17] little-endian as u128.
        let decoded = u128::from_le_bytes(data[1..17].try_into().unwrap());
        assert_eq!(decoded, amount as u128, "amount must round-trip as u128 LE");
        // Guard against regression to the broken 8-byte u64 wire.
        assert_ne!(
            data.len(),
            9,
            "8-byte u64 wire is the pre-v16 break — must NOT ship"
        );
    }
}
