use super::*;
use ckb_system_scripts::BUNDLED_CELL;
use ckb_testtool::context::Context;
use ckb_tool::ckb_crypto::secp::{Generator, Privkey};
use ckb_tool::ckb_hash::{blake2b_256, new_blake2b};
use ckb_tool::ckb_types::{
    bytes::Bytes,
    core::{TransactionBuilder, TransactionView, HeaderBuilder},
    packed::{self, *},
    prelude::*,
    H256,
};
use ckb_tool::ckb_types::packed::{Script, CellOutput};
use std::fs;
use std::iter::Extend;

const MAX_CYCLES: u64 = 10_000_000;

fn blake160(data: &[u8]) -> [u8; 20] {
    let mut buf = [0u8; 20];
    let hash = blake2b_256(data);
    buf.clone_from_slice(&hash[..20]);
    buf
}

fn sign_tx(tx: TransactionView, key: &Privkey) -> TransactionView {
    const SIGNATURE_SIZE: usize = 65;

    let witnesses_len = tx.witnesses().len();
    let tx_hash = tx.hash();
    let mut signed_witnesses: Vec<packed::Bytes> = Vec::new();
    let mut blake2b = new_blake2b();
    let mut message = [0u8; 32];
    blake2b.update(&tx_hash.raw_data());
    // digest the first witness
    let witness = WitnessArgs::default();
    let zero_lock: Bytes = {
        let mut buf = Vec::new();
        buf.resize(SIGNATURE_SIZE, 0);
        buf.into()
    };
    let witness_for_digest = witness
        .clone()
        .as_builder()
        .lock(Some(zero_lock).pack())
        .build();
    let witness_len = witness_for_digest.as_bytes().len() as u64;
    blake2b.update(&witness_len.to_le_bytes());
    blake2b.update(&witness_for_digest.as_bytes());
    (1..witnesses_len).for_each(|n| {
        let witness = tx.witnesses().get(n).unwrap();
        let witness_len = witness.raw_data().len() as u64;
        blake2b.update(&witness_len.to_le_bytes());
        blake2b.update(&witness.raw_data());
    });
    blake2b.finalize(&mut message);
    let message = H256::from(message);
    let sig = key.sign_recoverable(&message).expect("sign");
    signed_witnesses.push(
        witness
            .as_builder()
            .lock(Some(Bytes::from(sig.serialize())).pack())
            .build()
            .as_bytes()
            .pack(),
    );
    for i in 1..witnesses_len {
        signed_witnesses.push(tx.witnesses().get(i).unwrap());
    }
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

fn with_secp256k1_cell_deps(builder: TransactionBuilder, context: &mut Context)
    -> TransactionBuilder {
    let secp256k1_bin: Bytes =
        fs::read("../ckb-miscellaneous-scripts/build/secp256k1_blake2b_sighash_all_dual")
            .expect("load secp256k1")
            .into();
    let secp256k1_out_point = context.deploy_cell(secp256k1_bin);
    let secp256k1_dep = CellDep::new_builder()
        .out_point(secp256k1_out_point)
        .build();

    let secp256k1_data_bin = BUNDLED_CELL.get("specs/cells/secp256k1_data").unwrap();
    let secp256k1_data_out_point = context.deploy_cell(secp256k1_data_bin.to_vec().into());
    let secp256k1_data_dep = CellDep::new_builder()
        .out_point(secp256k1_data_out_point)
        .build();

    builder.cell_dep(secp256k1_dep).cell_dep(secp256k1_data_dep)
}

fn load_script(builder: TransactionBuilder, context: &mut Context, mut pubkey_hash: Vec<u8>)
    -> (TransactionBuilder, Script) {
    let contract_bin: Bytes = Loader::default().load_binary("time_lock");
    let out_point = context.deploy_cell(contract_bin);

    // Time limit info
    pubkey_hash.extend(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]);
    let lock_script = context
        .build_script(&out_point, pubkey_hash.to_vec().into())
        .expect("script");
    let lock_script_dep = CellDep::new_builder().out_point(out_point).build();

    (builder.cell_dep(lock_script_dep), lock_script)
}

fn bootstrap(builder: TransactionBuilder, context: &mut Context, pubkey_hash: Vec<u8>)
    -> (TransactionBuilder, Script) {
    let builder = with_secp256k1_cell_deps(builder, context);

    load_script(builder, context, pubkey_hash)
}


fn with_time_header(builder: TransactionBuilder, context: &mut Context, timestamp: u64)
    -> TransactionBuilder {
    let header = HeaderBuilder::default()
        .timestamp(timestamp.pack())
        .build();
    context.insert_header(header.clone());

    builder.header_dep(header.hash())
}

fn new_cell_output(capacity: u64, script: &Script) -> CellOutput {
    CellOutput::new_builder().capacity(capacity.pack()).lock(script.clone()).build()
}

#[test]
fn test_time_limit_not_reached_with_correct_key() {
    // generate key pair
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = blake160(&pubkey.serialize()).to_vec();

    let mut context = Context::default();
    let (tx_builder, lock_script) = bootstrap(
        TransactionBuilder::default(),
        &mut context,
        pubkey_hash,
    );
    let tx_builder = with_time_header(tx_builder, &mut context, 100);

    // prepare cells
    let input_out_point = context.create_cell(new_cell_output(1000, &lock_script), Bytes::new());
    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .build();

    let outputs = vec![new_cell_output(500, &lock_script), new_cell_output(500, &lock_script)];
    let outputs_data = vec![Bytes::new(); 2];

    // build transaction
    let tx = tx_builder
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();
    let tx = context.complete_tx(tx);
    let tx = sign_tx(tx, &privkey);

    // run
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect_err("pass verification");
}

#[test]
fn test_sign_with_wrong_key() {
    // generate key pair
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = blake160(&pubkey.serialize()).to_vec();
    let wrong_privkey = Generator::random_privkey();

    let mut context = Context::default();
    let (tx_builder, lock_script) = bootstrap(
        TransactionBuilder::default(),
        &mut context,
        pubkey_hash,
    );
    let tx_builder = with_time_header(tx_builder, &mut context, 1000);

    // prepare cells
    let input_out_point = context.create_cell(new_cell_output(1000, &lock_script), Bytes::new());
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![new_cell_output(500, &lock_script), new_cell_output(500, &lock_script)];

    let outputs_data = vec![Bytes::new(); 2];

    // build transaction
    let tx = tx_builder
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();
    let tx = context.complete_tx(tx);

    let tx = sign_tx(tx, &wrong_privkey);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect_err("pass verification");
}

#[test]
fn test_sign_with_correct_key() {
    // generate key pair
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = blake160(&pubkey.serialize()).to_vec();

    let mut context = Context::default();
    let (tx_builder, lock_script) = bootstrap(
        TransactionBuilder::default(),
        &mut context,
        pubkey_hash,
    );
    let tx_builder = with_time_header(tx_builder, &mut context, 1000);

    // prepare cells
    let input_out_point = context.create_cell(new_cell_output(1000, &lock_script), Bytes::new());
    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .build();

    let outputs = vec![new_cell_output(500, &lock_script), new_cell_output(500, &lock_script)];
    let outputs_data = vec![Bytes::new(); 2];

    // build transaction
    let tx = tx_builder
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();
    let tx = context.complete_tx(tx);
    let tx = sign_tx(tx, &privkey);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_multiple_time() {
    // generate key pair
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = blake160(&pubkey.serialize()).to_vec();

    let mut context = Context::default();
    let (tx_builder, lock_script) = bootstrap(
        TransactionBuilder::default(),
        &mut context,
        pubkey_hash,
    );
    let tx_builder = with_time_header(tx_builder, &mut context, 100);
    let tx_builder = with_time_header(tx_builder, &mut context, 1000);

    // prepare cells
    let input_out_point = context.create_cell(new_cell_output(1000, &lock_script), Bytes::new());
    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .build();

    let outputs = vec![new_cell_output(500, &lock_script), new_cell_output(500, &lock_script)];
    let outputs_data = vec![Bytes::new(); 2];

    // build transaction
    let tx = tx_builder
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();
    let tx = context.complete_tx(tx);
    let tx = sign_tx(tx, &privkey);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}
