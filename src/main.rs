use base64ct::{Base64UrlUnpadded, Encoder};
use chia::{
    clvm_traits::{self, clvm_quote, FromClvm, ToClvm},
    clvm_utils::{CurriedProgram, ToTreeHash},
    consensus::gen::{
        conditions::EmptyVisitor,
        flags::ALLOW_BACKREFS,
        run_block_generator::{run_block_generator, run_block_generator2},
        solution_generator::{solution_generator, solution_generator_backrefs},
    },
    protocol::{Bytes, Bytes32, BytesImpl, Coin},
    puzzles::standard::DEFAULT_HIDDEN_PUZZLE_HASH,
};
use chia_wallet_sdk::{conditions::CreateCoinWithoutMemos, driver::SpendContext};
use clvmr::{
    chia_dialect::ENABLE_BASE64_OPS_OUTSIDE_GUARD,
    serde::{node_from_bytes_backrefs, node_to_bytes, node_to_bytes_backrefs},
    sha2::{Digest, Sha256},
    Allocator,
};
use hex_literal::hex;
use p256::ecdsa::{signature::SignerMut, signature::Verifier, Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::group::GroupEncoding;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

const GENESIS_CHALLENGE: [u8; 32] =
    hex!("ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb");

fn main() -> anyhow::Result<()> {
    let max_cost = (11_000_000_000.0 * 0.7) as u64;

    for (backrefs, quantity, mod_puzzle) in [
        (false, 503, PASSKEY_PUZZLE.as_ref()),
        (true, 1046, PASSKEY_PUZZLE.as_ref()),
        (false, 327, PASSKEY_PUZZLE_IN_CLVM.as_ref()),
        (true, 1022, PASSKEY_PUZZLE_IN_CLVM.as_ref()),
    ] {
        let mut allocator = Allocator::new();
        let passkey_puzzle = node_from_bytes_backrefs(&mut allocator, mod_puzzle)?;

        let mut spends = Vec::new();

        for i in 0..quantity {
            let ctx = &mut SpendContext::new(&mut allocator);

            let delegated_puzzle = ctx.alloc(clvm_quote!([CreateCoinWithoutMemos {
                puzzle_hash: i.tree_hash().into(),
                amount: 1
            }]))?;
            let delegated_puzzle_hash = ctx.tree_hash(delegated_puzzle);

            let mut signing_key = SigningKey::random(&mut ChaCha8Rng::seed_from_u64(0));
            let verifying_key = VerifyingKey::from(&signing_key);
            let secp_pk = SecpPublicKey::new(verifying_key.as_affine().to_bytes().into());

            let puzzle = ctx.alloc(&CurriedProgram {
                program: passkey_puzzle,
                args: PasskeyArgs {
                    genesis_challenge: GENESIS_CHALLENGE.into(),
                    secp_pk,
                    hidden_puzzle_hash: DEFAULT_HIDDEN_PUZZLE_HASH.into(),
                },
            })?;

            let puzzle_hash = ctx.tree_hash(puzzle);

            let coin = Coin::new(i.tree_hash().into(), puzzle_hash.into(), 1);

            let authenticator_data = hex!("49960e049a50ddbbdce799e5b7f3e6ae91cd93f580318ae14e0100c41a2d6b25120000000101002e68dfe9fbc3e53a5f29de8d3d0f54b500e5e2fdf4898f5de4e4e1af79ef0342");
            let challenge = challenge(
                delegated_puzzle_hash.into(),
                coin.coin_id(),
                GENESIS_CHALLENGE.into(),
                DEFAULT_HIDDEN_PUZZLE_HASH.into(),
            );
            let challenge_base64 = String::from_utf8(base64url_encode(challenge)).unwrap();
            let client_data_json = format!(
                r#"{{"type":"webauthn.create","challenge":"{challenge_base64}","origin":"https://example.com","crossOrigin":false}}"#
            );
            let challenge_index = 26;

            let message = [
                authenticator_data.to_vec(),
                sha256(&client_data_json).to_vec(),
            ]
            .concat();

            let signature: Signature = signing_key.sign(&message);
            assert!(verifying_key.verify(&message, &signature).is_ok());

            let signature = SecpSignature::new(signature.to_bytes().to_vec().try_into().unwrap());

            let solution = ctx.alloc(&PasskeySolution {
                authenticator_data: authenticator_data.to_vec().into(),
                client_data_json: client_data_json.as_bytes().to_vec().into(),
                challenge_index,
                delegated_puzzle,
                delegated_solution: (),
                signature,
                coin_id: coin.coin_id(),
            })?;

            if backrefs {
                let puzzle_reveal = node_to_bytes_backrefs(&allocator, puzzle)?;
                let solution = node_to_bytes_backrefs(&allocator, solution)?;
                spends.push((coin, puzzle_reveal, solution));
            } else {
                let puzzle_reveal = node_to_bytes(&allocator, puzzle)?;
                let solution = node_to_bytes(&allocator, solution)?;
                spends.push((coin, puzzle_reveal, solution));
            }
        }

        println!(
            "backrefs = {}, spends = {}, clvm_implementation = {}",
            backrefs,
            quantity,
            mod_puzzle == PASSKEY_PUZZLE_IN_CLVM
        );

        if backrefs {
            let generator = solution_generator_backrefs(spends)?;
            let conds = run_block_generator2::<&[u8], EmptyVisitor>(
                &mut allocator,
                &generator,
                &[],
                max_cost,
                ENABLE_BASE64_OPS_OUTSIDE_GUARD | ALLOW_BACKREFS,
            )?;
            println!("Total block cost: {}", conds.cost);
        } else {
            let generator = solution_generator(spends)?;
            let conds = run_block_generator::<&[u8], EmptyVisitor>(
                &mut allocator,
                &generator,
                &[],
                max_cost,
                ENABLE_BASE64_OPS_OUTSIDE_GUARD,
            )?;
            println!("Total block cost: {}", conds.cost);
        }
    }

    Ok(())
}

fn base64url_encode(data: impl AsRef<[u8]>) -> Vec<u8> {
    let data = data.as_ref();
    let mut output = vec![0; encoded_len(data.len()).unwrap()];
    let mut encoder = Encoder::<Base64UrlUnpadded>::new(&mut output[..]).unwrap();
    encoder.encode(data).unwrap();
    encoder.finish().unwrap();
    output
}

fn encoded_len(n: usize) -> Option<usize> {
    let q = n.checked_mul(4)?;
    Some((q / 3) + (q % 3 != 0) as usize)
}

fn sha256(data: impl AsRef<[u8]>) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    Bytes32::new(hasher.finalize().into())
}

fn challenge(
    delegated_puzzle_hash: Bytes32,
    coin_id: Bytes32,
    genesis_challenge: Bytes32,
    hidden_puzzle_hash: Bytes32,
) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(delegated_puzzle_hash);
    hasher.update(coin_id);
    hasher.update(genesis_challenge);
    hasher.update(hidden_puzzle_hash);
    Bytes32::new(hasher.finalize().into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm, Hash)]
#[clvm(curry)]
struct PasskeyArgs {
    genesis_challenge: Bytes32,
    secp_pk: SecpPublicKey,
    hidden_puzzle_hash: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq, ToClvm, FromClvm, Hash)]
#[clvm(list)]
struct PasskeySolution<P, S> {
    authenticator_data: Bytes,
    client_data_json: Bytes,
    challenge_index: usize,
    delegated_puzzle: P,
    delegated_solution: S,
    signature: SecpSignature,
    coin_id: Bytes32,
}

type SecpPublicKey = BytesImpl<33>;
type SecpSignature = BytesImpl<64>;

const PASSKEY_PUZZLE: [u8; 389] = hex!("ff02ffff01ff02ff0affff04ff02ffff04ff03ffff04ffff02ff04ffff04ff02ffff04ff82017fff80808080ff8080808080ffff04ffff01ffff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff04ffff04ff02ffff04ff09ff80808080ffff02ff04ffff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ffff02ff0effff04ff02ffff04ff03ffff04ffff3effff0bff0bff8217fdff09ff2d8080ff8080808080ff02ffff03ffff09ff15ff5980ffff01ff02ff8205f9ff820bf980ffff01ff02ffff03ffff09ffff0cff820179ff8202f9ffff10ff8202f9ffff0dffff0effff018d226368616c6c656e6765223a22ff0bffff012280808080ffff0effff018d226368616c6c656e6765223a22ff0bffff01228080ffff01ff04ffff04ffff0101ffff841c3a8f00ff29ffff0bff8200b9ffff0bff8201798080ff8217f98080ffff04ffff04ffff0146ffff04ff822ff9ff808080ffff02ff8205f9ff820bf9808080ffff01ff088080ff018080ff0180ff018080");
const PASSKEY_PUZZLE_IN_CLVM: [u8; 991] = hex!("ff02ffff01ff02ff16ffff04ff02ffff04ff03ffff04ffff02ff10ffff04ff02ffff04ff82017fff80808080ff8080808080ffff04ffff01ffffffff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff10ffff04ff02ffff04ff09ff80808080ffff02ff10ffff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff0cffff01c0404142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738392d5fff05ffff10ff05ffff01018080ffff0effff02ff18ffff04ff02ffff04ffff17ff05ffff0181fe80ff80808080ffff02ff18ffff04ff02ffff04ffff19ffff17ffff18ff05ffff010380ffff010480ffff17ff0bffff0181fc8080ff80808080ffff02ff18ffff04ff02ffff04ffff19ffff17ffff18ff0bffff010f80ffff010280ffff17ff17ffff0181fa8080ff80808080ffff02ff18ffff04ff02ffff04ffff18ff17ffff013f80ff8080808080ff02ff12ffff04ff02ffff04ff03ffff04ffff0cff05ff80ffff010180ff8080808080ffffff02ffff03ffff15ff15ffff010280ffff01ff0effff02ff14ffff04ff02ffff04ff0bffff04ffff0cff09ffff0101ffff010280ffff04ffff0cff09ffff0102ffff010380ff808080808080ffff02ff1cffff04ff02ffff04ffff0cff09ffff010380ffff04ffff11ff15ffff010380ff808080808080ffff01ff02ffff03ffff09ff15ffff010280ffff01ff0effff0cffff02ff14ffff04ff02ffff04ff0bffff04ffff0cff09ffff010180ffff04ff80ff808080808080ff80ffff01038080ffff01ff02ffff03ffff09ff15ffff010180ffff01ff0cffff02ff14ffff04ff02ffff04ff09ffff04ff80ffff04ff80ff808080808080ff80ffff010280ffff01ff018080ff018080ff018080ff0180ff02ff1cffff04ff02ffff04ff05ffff04ffff0dff0580ff8080808080ffff02ff1effff04ff02ffff04ff03ffff04ffff02ff1affff04ff02ffff04ffff0bff0bff8217fdff09ff2d80ff80808080ff8080808080ff02ffff03ffff09ff15ff5980ffff01ff02ff8205f9ff820bf980ffff01ff02ffff03ffff09ffff0cff820179ff8202f9ffff10ff8202f9ffff0dffff0effff018d226368616c6c656e6765223a22ff0bffff012280808080ffff0effff018d226368616c6c656e6765223a22ff0bffff01228080ffff01ff04ffff04ffff0101ffff841c3a8f00ff29ffff0bff8200b9ffff0bff8201798080ff8217f98080ffff04ffff04ffff0146ffff04ff822ff9ff808080ffff02ff8205f9ff820bf9808080ffff01ff088080ff018080ff0180ff018080");
