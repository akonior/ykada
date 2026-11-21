use std::ops::Range;

use pallas_codec::minicbor::{self, data::Type, Decoder, Encoder};
use pallas_primitives::{conway, Fragment};

use super::cbor::{items, read_item, DecodeResult};
use crate::error::{YkadaError, YkadaResult};

// Witness-set key of the vkey witnesses.
const VKEY_WITNESSES: u64 = 0;
// Tag 258 marks a set; some tools write a plain array instead. Both are kept as found.
const SET_TAG: u64 = 258;

// Add `witness`, replacing an earlier one for the same key. Only the vkey witness list is
// rewritten: the body, the other witness fields and the rest of the transaction keep their bytes,
// so the tx ID, script hashes and a fee computed for that encoding all stay valid.
pub(crate) fn attach_witness(
    tx_cbor: &[u8],
    witness: &conway::VKeyWitness,
) -> YkadaResult<Vec<u8>> {
    let span = witness_set_span(tx_cbor).map_err(malformed)?;
    let witness_set = with_vkey_witness(&tx_cbor[span.clone()], witness)?;
    Ok([&tx_cbor[..span.start], &witness_set, &tx_cbor[span.end..]].concat())
}

fn malformed(e: minicbor::decode::Error) -> YkadaError {
    YkadaError::Tx(format!("invalid transaction CBOR: {e}"))
}

fn encoding_failed<E: std::fmt::Display>(e: E) -> YkadaError {
    YkadaError::Tx(format!("failed to encode signed tx: {e}"))
}

// A transaction is [body, witness set, is_valid, auxiliary data].
fn witness_set_span(tx: &[u8]) -> DecodeResult<Range<usize>> {
    let mut d = Decoder::new(tx);
    d.array()?;
    d.skip()?;
    let start = d.position();
    d.skip()?;
    Ok(start..d.position())
}

struct Entry {
    key: u64,
    key_bytes: Range<usize>,
    value: Range<usize>,
}

fn with_vkey_witness(witness_set: &[u8], witness: &conway::VKeyWitness) -> YkadaResult<Vec<u8>> {
    let mut d = Decoder::new(witness_set);
    let length = d.map().map_err(malformed)?;
    let entries = items(&mut d, length, read_entry).map_err(malformed)?;
    let existing = entries.iter().find(|e| e.key == VKEY_WITNESSES);
    let vkeys = vkey_list_with(existing.map(|e| &witness_set[e.value.clone()]), witness)?;
    let rewritten = |e: &Entry| match e.key == VKEY_WITNESSES {
        true => [&witness_set[e.key_bytes.clone()], vkeys.as_slice()].concat(),
        false => witness_set[e.key_bytes.start..e.value.end].to_vec(),
    };
    let added = match existing {
        Some(_) => vec![],
        None => [
            encode(|e| e.u64(VKEY_WITNESSES).map(|_| ()))?,
            vkeys.clone(),
        ]
        .concat(),
    };
    let body: Vec<u8> = added
        .into_iter()
        .chain(entries.iter().flat_map(rewritten))
        .collect();
    let count = entries.len() as u64 + u64::from(existing.is_none());
    framed(Container::Map, length.map(|_| count), body)
}

// The vkey witnesses with ours added, in the encoding the transaction already used.
fn vkey_list_with(existing: Option<&[u8]>, witness: &conway::VKeyWitness) -> YkadaResult<Vec<u8>> {
    let ours = witness.encode_fragment().map_err(encoding_failed)?;
    match existing {
        None => Ok([
            encode(|e| e.tag(minicbor::data::Tag::new(SET_TAG)).map(|_| ()))?,
            framed(Container::Array, Some(1), ours)?,
        ]
        .concat()),
        Some(list) => {
            let mut d = Decoder::new(list);
            let tag_end = match d.datatype().map_err(malformed)? {
                Type::Tag => d.tag().map(|_| d.position()).map_err(malformed)?,
                _not_a_tag => 0,
            };
            let length = d.array().map_err(malformed)?;
            let kept: Vec<&[u8]> = items(&mut d, length, read_item)
                .map_err(malformed)?
                .into_iter()
                .map(|range| &list[range])
                .filter(|item| !same_key(item, witness))
                .collect();
            let count = kept.len() as u64 + 1;
            let body = kept.concat().into_iter().chain(ours).collect();
            let array = framed(Container::Array, length.map(|_| count), body)?;
            Ok([&list[..tag_end], array.as_slice()].concat())
        }
    }
}

fn same_key(item: &[u8], witness: &conway::VKeyWitness) -> bool {
    conway::VKeyWitness::decode_fragment(item).is_ok_and(|w| w.vkey == witness.vkey)
}

fn read_entry(d: &mut Decoder<'_>) -> DecodeResult<Entry> {
    let start = d.position();
    let key = d.u64()?;
    let value = read_item(d)?;
    Ok(Entry {
        key,
        key_bytes: start..value.start,
        value,
    })
}

#[derive(Clone, Copy)]
enum Container {
    Map,
    Array,
}

// `body` inside a definite header for `count` items, or between indefinite-length markers.
fn framed(container: Container, count: Option<u64>, body: Vec<u8>) -> YkadaResult<Vec<u8>> {
    let header = match (container, count) {
        (Container::Map, Some(n)) => encode(|e| e.map(n).map(|_| ()))?,
        (Container::Array, Some(n)) => encode(|e| e.array(n).map(|_| ()))?,
        (Container::Map, None) => vec![0xbf],
        (Container::Array, None) => vec![0x9f],
    };
    let trailer = match count {
        Some(_) => vec![],
        None => vec![0xff],
    };
    Ok([header, body, trailer].concat())
}

fn encode(
    write: impl FnOnce(
        &mut Encoder<Vec<u8>>,
    ) -> Result<(), minicbor::encode::Error<std::convert::Infallible>>,
) -> YkadaResult<Vec<u8>> {
    let mut encoder = Encoder::new(Vec::new());
    write(&mut encoder).map_err(encoding_failed)?;
    Ok(encoder.into_writer())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn witness(seed: u8) -> conway::VKeyWitness {
        conway::VKeyWitness {
            vkey: vec![seed; 32].into(),
            signature: vec![seed; 64].into(),
        }
    }

    fn encoded(seed: u8) -> Vec<u8> {
        witness(seed).encode_fragment().unwrap()
    }

    // [body, witness set, is_valid, no auxiliary data]; the body is an empty map here.
    fn tx(witness_set: &[u8]) -> Vec<u8> {
        [&[0x84, 0xa0], witness_set, &[0xf5, 0xf6]].concat()
    }

    fn witness_set_of(tx: &[u8]) -> Vec<u8> {
        tx[2..tx.len() - 2].to_vec()
    }

    fn attached(witness_set: &[u8], seed: u8) -> Vec<u8> {
        witness_set_of(&attach_witness(&tx(witness_set), &witness(seed)).unwrap())
    }

    const TAG_258: [u8; 3] = [0xd9, 0x01, 0x02];

    #[test]
    fn test_empty_witness_set_gets_a_tagged_set() {
        let expected = [&[0xa1, 0x00][..], &TAG_258, &[0x81], &encoded(1)].concat();
        assert_eq!(attached(&[0xa0], 1), expected);
    }

    // A plain array must stay a plain array: tagging it adds 3 bytes the fee may not cover.
    #[test]
    fn test_plain_vkey_array_stays_plain() {
        let before = [&[0xa1, 0x00, 0x81][..], &encoded(1)].concat();
        let expected = [&[0xa1, 0x00, 0x82][..], &encoded(1), &encoded(2)].concat();
        assert_eq!(attached(&before, 2), expected);
    }

    #[test]
    fn test_tagged_vkey_set_stays_tagged() {
        let before = [&[0xa1, 0x00][..], &TAG_258, &[0x81], &encoded(1)].concat();
        let expected = [
            &[0xa1, 0x00][..],
            &TAG_258,
            &[0x82],
            &encoded(1),
            &encoded(2),
        ]
        .concat();
        assert_eq!(attached(&before, 2), expected);
    }

    // Plutus scripts (key 7) written as a plain array keep their exact bytes.
    #[test]
    fn test_other_witness_fields_keep_their_bytes() {
        let scripts = [0x07, 0x81, 0x42, 0x01, 0x02];
        let before = [&[0xa1][..], &scripts].concat();
        let expected = [&[0xa2, 0x00][..], &TAG_258, &[0x81], &encoded(1), &scripts].concat();
        assert_eq!(attached(&before, 1), expected);
    }

    #[test]
    fn test_own_earlier_witness_is_replaced_in_place() {
        let other = conway::VKeyWitness {
            signature: vec![7; 64].into(),
            ..witness(1)
        };
        let before = [
            &[0xa1, 0x00, 0x82][..],
            &other.encode_fragment().unwrap(),
            &encoded(2),
        ]
        .concat();
        let expected = [&[0xa1, 0x00, 0x82][..], &encoded(2), &encoded(1)].concat();
        assert_eq!(attached(&before, 1), expected);
    }

    #[test]
    fn test_indefinite_map_and_array_stay_indefinite() {
        let before = [&[0xbf, 0x00, 0x9f][..], &encoded(1), &[0xff, 0xff]].concat();
        let expected = [
            &[0xbf, 0x00, 0x9f][..],
            &encoded(1),
            &encoded(2),
            &[0xff, 0xff],
        ]
        .concat();
        assert_eq!(attached(&before, 2), expected);
    }

    #[test]
    fn test_indefinite_map_without_vkeys_gets_them_first() {
        let scripts = [0x07, 0x81, 0x42, 0x01, 0x02];
        let before = [&[0xbf][..], &scripts, &[0xff]].concat();
        let expected = [
            &[0xbf, 0x00][..],
            &TAG_258,
            &[0x81],
            &encoded(1),
            &scripts,
            &[0xff],
        ]
        .concat();
        assert_eq!(attached(&before, 1), expected);
    }

    #[test]
    fn test_the_rest_of_the_transaction_is_untouched() {
        let body = [0xa1, 0x02, 0x19, 0x03, 0xe8];
        let aux = [0xa1, 0x00, 0x61, 0x78];
        let original = [&[0x84][..], &body, &[0xa0], &[0xf4], &aux].concat();
        let signed = attach_witness(&original, &witness(1)).unwrap();
        assert!(signed.starts_with(&[&[0x84][..], &body].concat()));
        assert!(signed.ends_with(&[&[0xf4][..], &aux].concat()));
    }

    #[test]
    fn test_truncated_input_is_an_error() {
        assert!(attach_witness(&[0x84, 0xa0], &witness(1)).is_err());
    }

    use proptest::prelude::*;
    use std::collections::BTreeMap;

    // A witness set of other fields (keys 1..=7), each a one-item array, plain or tagged.
    fn other_fields() -> impl Strategy<Value = BTreeMap<u8, Vec<u8>>> {
        prop::collection::btree_map(
            1u8..=7,
            (prop::collection::vec(any::<u8>(), 0..24), any::<bool>()),
            0..5,
        )
        .prop_map(|fields| {
            fields
                .into_iter()
                .map(|(key, (bytes, tagged))| {
                    let item = encode(|e| e.bytes(&bytes).map(|_| ())).unwrap();
                    let array = [vec![0x81], item].concat();
                    let value = match tagged {
                        true => [TAG_258.to_vec(), array].concat(),
                        false => array,
                    };
                    (key, [vec![key], value].concat())
                })
                .collect()
        })
    }

    proptest! {
        // Every other witness field comes out byte for byte, and attaching twice is the
        // same as attaching once.
        #[test]
        fn prop_other_fields_keep_their_bytes(fields in other_fields(), seed in any::<u8>()) {
            let header = encode(|e| e.map(fields.len() as u64).map(|_| ())).unwrap();
            let witness_set = [header, fields.values().flatten().copied().collect()].concat();
            let once = attach_witness(&tx(&witness_set), &witness(seed)).unwrap();
            let after = witness_set_of(&once);
            fields.values().for_each(|field| {
                assert!(after.windows(field.len()).any(|w| w == field.as_slice()), "lost {field:02x?}");
            });
            prop_assert_eq!(attach_witness(&once, &witness(seed)).unwrap(), once);
        }
    }
}
