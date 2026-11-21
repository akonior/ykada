use std::ops::Range;

use pallas_codec::minicbor::{self, data::Type, Decoder};

pub(crate) type DecodeResult<T> = Result<T, minicbor::decode::Error>;

// Reads the items of a definite or indefinite map or array, after its header.
pub(crate) fn items<T>(
    d: &mut Decoder<'_>,
    length: Option<u64>,
    read: fn(&mut Decoder<'_>) -> DecodeResult<T>,
) -> DecodeResult<Vec<T>> {
    match length {
        Some(n) => (0..n).map(|_| read(d)).collect(),
        None => std::iter::from_fn(|| match d.datatype() {
            Ok(Type::Break) => None,
            Ok(_) => Some(read(d)),
            Err(e) => Some(Err(e)),
        })
        .collect(),
    }
}

// The byte range of the next item, whatever it is.
pub(crate) fn read_item(d: &mut Decoder<'_>) -> DecodeResult<Range<usize>> {
    let start = d.position();
    d.skip()?;
    Ok(start..d.position())
}

// The keys of a map with unsigned keys, in order, repeats included.
pub(crate) fn map_keys(map: &[u8]) -> DecodeResult<Vec<u64>> {
    let mut d = Decoder::new(map);
    let length = d.map()?;
    items(&mut d, length, |d| {
        let key = d.u64()?;
        d.skip().map(|()| key)
    })
}
