use core::result::Result;

use ckb_std::{
    debug,
    high_level::{load_script, load_header},
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, prelude::*},
    dynamic_loading_c_impl::CKBDLContext,
};

use crate::error::Error;

use ckb_lib_secp256k1::LibSecp256k1;

pub fn main() -> Result<(), Error> {
    let script = load_script()?;
    let args: Bytes = script.args().unpack();

    if args.len() != 28 {
        return Err(Error::Encoding);
    }

    let pubkey = args.slice(0..20);
    let time_limit = args.slice(20..28);

    // Check time limit
    let timestamp = match load_header(0, Source::HeaderDep) {
        Ok(header) => header.raw().timestamp().unpack().to_be_bytes(),
        Err(_) => return Err(Error::CurrentTimeNotGiven),
    };

    if time_limit.gt(&timestamp) {
        return Err(Error::TimeLimitNotReached);
    }

    // create a DL context with 128K buffer size
    let mut context = unsafe{ CKBDLContext::<[u8; 128 * 1024]>::new()};
    let lib = LibSecp256k1::load(&mut context);

    test_validate_blake2b_sighash_all(&lib, &pubkey)

}

fn test_validate_blake2b_sighash_all(
    lib: &LibSecp256k1,
    expected_pubkey_hash: &[u8],
) -> Result<(), Error> {
    let mut pubkey_hash = [0u8; 20];
    lib.validate_blake2b_sighash_all(&mut pubkey_hash)
        .map_err(|_err_code| {
            debug!("secp256k1 error {}", _err_code);
            Error::Secp256k1
        })?;

    // compare with expected pubkey_hash
    if &pubkey_hash[..] != expected_pubkey_hash {
        return Err(Error::WrongPubkey);
    }
    Ok(())
}
