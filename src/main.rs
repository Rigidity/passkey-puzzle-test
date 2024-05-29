use base64ct::{Base64UrlUnpadded, Encoder};
use chia::{
    clvm_traits::{self, clvm_quote, FromClvm, ToClvm},
    clvm_utils::{CurriedProgram, TreeHash},
    consensus::gen::{
        conditions::EmptyVisitor, flags::MEMPOOL_MODE, run_block_generator::run_block_generator,
        solution_generator::solution_generator,
    },
    protocol::{Bytes, Bytes32, BytesImpl, Coin},
    puzzles::standard::DEFAULT_HIDDEN_PUZZLE_HASH,
};
use chia_wallet_sdk::driver::SpendContext;
use clvmr::{
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
    let mut allocator = Allocator::new();
    let ctx = &mut SpendContext::new(&mut allocator);

    let passkey_puzzle = ctx.puzzle(PASSKEY_PUZZLE_HASH, &PASSKEY_PUZZLE)?;

    let delegated_puzzle = ctx.alloc(clvm_quote!(()))?;
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
    let puzzle_reveal = ctx.serialize(puzzle)?;
    println!("Puzzle Reveal: {:?}", puzzle_reveal);

    let puzzle_hash = ctx.tree_hash(puzzle);

    let coin = Coin::new(Bytes32::new([1; 32]), puzzle_hash.into(), 1);

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

    let solution = ctx.serialize(&PasskeySolution {
        authenticator_data: authenticator_data.to_vec().into(),
        client_data_json: client_data_json.as_bytes().to_vec().into(),
        challenge_index,
        delegated_puzzle,
        delegated_solution: (),
        signature,
        coin_id: coin.coin_id(),
    })?;

    println!("Solution: {:?}", solution);

    let generator = solution_generator([(coin, puzzle_reveal, solution)])?;
    let conds = run_block_generator::<&[u8], EmptyVisitor>(
        &mut allocator,
        &generator,
        &[],
        u64::MAX,
        MEMPOOL_MODE,
    )?;
    dbg!(conds);

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

const PASSKEY_PUZZLE: [u8; 1610] = hex!("ff02ffff01ff02ff2effff04ff02ffff04ff03ffff04ffff02ff10ffff04ff02ffff04ff82017fff80808080ff8080808080ffff04ffff01ffffffff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff10ffff04ff02ffff04ff09ff80808080ffff02ff10ffff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ffff02ffff03ffff21ffff09ff0bffff0dff178080ffff15ff0bffff0dff17808080ffff01ff0180ffff01ff04ffff02ff05ffff04ffff0cff17ff0bffff10ff0bffff01038080ff808080ffff02ff28ffff04ff02ffff04ff05ffff04ffff10ff0bffff010380ffff04ff17ff8080808080808080ff0180ff02ffff03ff0bffff01ff02ffff03ff13ffff01ff04ffff02ff05ffff04ff23ff808080ffff02ff38ffff04ff02ffff04ff05ffff04ffff04ff33ff1b80ff808080808080ffff01ff02ff38ffff04ff02ffff04ff05ffff04ff1bff808080808080ff0180ffff01ff018080ff0180ffff0cffff01c0404142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738392d5fff05ffff10ff05ffff01018080ffff02ff3cffff04ff02ffff04ff03ffff04ffff06ffff14ffff0dff0580ffff01038080ff8080808080ff02ff12ffff04ff02ffff04ff03ffff04ffff02ffff03ff0bffff01ff11ffff0103ff0b80ffff01ff018080ff0180ff8080808080ffffff02ff2affff04ff02ffff04ff03ffff04ffff0eff11ffff0cffff0183000000ff80ff0b8080ff8080808080ffff02ff36ffff04ff02ffff04ff03ffff04ffff02ff28ffff04ff02ffff04ffff04ffff0102ffff04ffff04ffff0101ffff04ffff0102ffff04ffff04ffff0101ff2680ffff04ffff04ffff0104ffff04ffff04ffff0101ff0280ffff04ffff0101ff80808080ff8080808080ffff04ffff04ffff0104ffff04ffff04ffff0101ffff04ff15ff808080ffff04ffff0101ff80808080ff80808080ffff04ff80ffff04ff0bff808080808080ff8080808080ff04ff4fffff04ffff19ffff16ff6fffff010480ff2780ffff04ffff19ffff16ff37ffff010280ff1380ffff04ff1bff8080808080ffffff02ff3affff04ff02ffff04ffff04ffff04ff09ff8080ffff04ff0bff808080ffff04ffff14ffff02ffff03ffff15ffff0cff0bffff0102ffff010380ffff0181ff80ffff01ff0cff0bffff0102ffff010380ffff01ff10ffff0cff0bffff0102ffff010380ffff018201008080ff0180ffff014080ffff04ffff14ffff02ffff03ffff15ffff0cff0bffff0101ffff010280ffff0181ff80ffff01ff0cff0bffff0101ffff010280ffff01ff10ffff0cff0bffff0101ffff010280ffff018201008080ff0180ffff011080ffff04ffff14ffff02ffff03ffff15ffff0cff0bff80ffff010180ffff0181ff80ffff01ff0cff0bff80ffff010180ffff01ff10ffff0cff0bff80ffff010180ffff018201008080ff0180ffff010480ff80808080808080ff0cffff02ffff04ffff04ffff010eff8080ffff02ff38ffff04ff02ffff04ffff04ffff0102ffff04ffff04ffff0101ff1480ffff04ffff04ffff0104ffff04ffff04ffff0101ff0280ffff04ffff0101ff80808080ff80808080ffff04ff0bff808080808080ff8080ff80ffff11ffff0dffff02ffff04ffff04ffff010eff8080ffff02ff38ffff04ff02ffff04ffff04ffff0102ffff04ffff04ffff0101ff1480ffff04ffff04ffff0104ffff04ffff04ffff0101ff0280ffff04ffff0101ff80808080ff80808080ffff04ff0bff808080808080ff808080ff298080ffff02ff3effff04ff02ffff04ff03ffff04ffff02ff2cffff04ff02ffff04ffff0bff0bff8217fdff09ff2d80ff80808080ff8080808080ff02ffff03ffff09ff15ff5980ffff01ff02ff8205f9ff820bf980ffff01ff02ffff03ffff09ffff0cff820179ff8202f9ffff10ff8202f9ffff0dffff0effff018d226368616c6c656e6765223a22ff0bffff012280808080ffff0effff018d226368616c6c656e6765223a22ff0bffff01228080ffff01ff04ffff04ffff0101ffff841c3a8f00ff29ffff0bff8200b9ffff0bff8201798080ff8217f98080ffff04ffff04ffff0146ffff04ff822ff9ff808080ffff02ff8205f9ff820bf9808080ffff01ff088080ff018080ff0180ff018080");
const PASSKEY_PUZZLE_HASH: TreeHash = TreeHash::new(hex!(
    "fc5e5fc8ba0ff4623c26d60dcfc7ddbe7b5a644ac0d95b85e5d60b9392679298"
));
