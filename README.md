# Time lock script for Nervos Network

This is a lock script (smart contract) allows user to avoid consumption of a
cell before specified time. After time limit, user still have to sign the
transaction with their private key to consume the cell.

## Lock argument

Arguments format:

```
| Lock argument | Time limit |
    20 bytes       8 bytes
```

Lock argument is same as that used for `secp256k1_blake160_sighash_all` system
script.

Time limit is a big endian `u64`, represents an absolute Unix time stamp in
milliseconds.

## Unlock proof

To unlock a cell with this script, user have to append some block headers to the
`header_deps` field of transaction as time proof. If all those headers' time
stamp is earlier than the time limit, the cell won't be unlocked.

This script needs three cell dependencies:

* The script cell itself.
* The `secp256k1_blake2b_sighash_all_dual` shared library.
* The `specs/cells/secp256k1_data` system script/cell.

## Building

Build contracts:

``` sh
capsule build
```

Or in release mode:

``` sh
capsule build --release
```

Run tests:

``` sh
capsule test
```

Build shared library:

```
cd ckb-miscellaneous-scripts
make all-via-docker
```

`ckb-miscellaneous-scripts/build/secp256k1_blake2b_sighash_all_dual` is what we
want.
