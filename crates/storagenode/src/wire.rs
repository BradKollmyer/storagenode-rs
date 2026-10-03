//! Protobuf fields the generated types do not have.
//!
//! prost drops a field it does not know. The Go node keeps it and writes it
//! back after the known fields, both when it checks a signature and when it
//! stores or forwards the message. A satellite that adds a field to
//! `OrderLimit` therefore still works with an older Go node. Here that field
//! has to be carried by hand: this module finds it and puts it back.

use std::ops::RangeInclusive;

/// Field numbers of `orders.OrderLimit` in the vendored proto.
pub(crate) const ORDER_LIMIT_FIELDS: RangeInclusive<u32> = 1..=15;

const VARINT: u64 = 0;
const FIXED64: u64 = 1;
const LEN: u64 = 2;
const FIXED32: u64 = 5;

struct Field<'a> {
    number: u32,
    /// Key and value, as they are on the wire.
    raw: &'a [u8],
    /// The payload of a length-delimited field.
    payload: Option<&'a [u8]>,
}

fn varint(input: &[u8]) -> Option<(u64, &[u8])> {
    let mut value = 0u64;
    for (index, byte) in input.iter().enumerate().take(10) {
        value |= u64::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            return Some((value, &input[index + 1..]));
        }
    }
    None
}

/// The first field of `input` and what follows it. `None` for a group, a
/// zero field number, or a value that runs past the end.
fn first_field(input: &[u8]) -> Option<(Field<'_>, &[u8])> {
    let (key, after_key) = varint(input)?;
    let number = u32::try_from(key >> 3).ok().filter(|number| *number > 0)?;
    let (payload, rest) = match key & 7 {
        VARINT => (None, varint(after_key)?.1),
        FIXED64 => (None, after_key.get(8..)?),
        FIXED32 => (None, after_key.get(4..)?),
        LEN => {
            let (len, after_len) = varint(after_key)?;
            let len = usize::try_from(len).ok()?;
            (Some(after_len.get(..len)?), after_len.get(len..)?)
        }
        _ => return None,
    };
    let raw = &input[..input.len() - rest.len()];
    Some((
        Field {
            number,
            raw,
            payload,
        },
        rest,
    ))
}

/// The top-level fields of `message` whose numbers are not in `known`, as
/// they are on the wire and in their order. Empty when there are none.
/// `None` when `message` does not parse.
pub(crate) fn unknown_fields(message: &[u8], known: RangeInclusive<u32>) -> Option<Vec<u8>> {
    let mut unknown = Vec::new();
    let mut rest = message;
    while !rest.is_empty() {
        let (field, after) = first_field(rest)?;
        if !known.contains(&field.number) {
            unknown.extend_from_slice(field.raw);
        }
        rest = after;
    }
    Some(unknown)
}

/// The bytes of the embedded message in field `number`. `None` when the
/// field is absent, is not length-delimited, or appears more than once.
pub(crate) fn embedded(message: &[u8], number: u32) -> Option<&[u8]> {
    let mut found = None;
    let mut rest = message;
    while !rest.is_empty() {
        let (field, after) = first_field(rest)?;
        if field.number == number {
            if found.is_some() {
                return None;
            }
            found = Some(field.payload?);
        }
        rest = after;
    }
    found
}

/// Appends `value` to `out` as the embedded message in field `number`.
pub(crate) fn put_embedded(out: &mut Vec<u8>, number: u32, value: &[u8]) {
    put_varint(out, (u64::from(number) << 3) | LEN);
    put_varint(out, u64::try_from(value.len()).unwrap_or(u64::MAX));
    out.extend_from_slice(value);
}

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value & 0x7f) as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

#[cfg(test)]
mod tests {
    use prost::Message;
    use storj_proto::orders::{Order, OrderLimit, SettlementRequest};

    use super::*;

    #[test]
    fn unknown_fields_are_found_and_known_ones_left() {
        let limit = OrderLimit {
            serial_number: vec![1; 16],
            limit: 300,
            action: 2,
            order_creation: Some(prost_types::Timestamp {
                seconds: 1_700_000_000,
                nanos: 5,
            }),
            deprecated_satellite_address: None,
            ..OrderLimit::default()
        };
        let known = limit.encode_to_vec();
        assert_eq!(
            unknown_fields(&known, ORDER_LIMIT_FIELDS).unwrap(),
            Vec::<u8>::new()
        );

        // Field 16 as bytes, field 17 as a varint, field 18 as fixed32,
        // field 19 as fixed64.
        let mut extra = Vec::new();
        put_embedded(&mut extra, 16, b"future");
        put_varint(&mut extra, (17 << 3) | VARINT);
        put_varint(&mut extra, 300);
        put_varint(&mut extra, (18 << 3) | FIXED32);
        extra.extend_from_slice(&[1, 2, 3, 4]);
        put_varint(&mut extra, (19 << 3) | FIXED64);
        extra.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let mut wire = known.clone();
        wire.extend_from_slice(&extra);
        assert_eq!(unknown_fields(&wire, ORDER_LIMIT_FIELDS).unwrap(), extra);
        // prost reads the same known fields with the extra ones present.
        assert_eq!(OrderLimit::decode(wire.as_slice()).unwrap(), limit);

        // A value that runs past the end, and a group, do not parse.
        let mut short = Vec::new();
        put_varint(&mut short, (16 << 3) | LEN);
        short.extend_from_slice(&[5, b'x']);
        assert!(unknown_fields(&short, ORDER_LIMIT_FIELDS).is_none());
        assert!(unknown_fields(&[(1 << 3) | 3], ORDER_LIMIT_FIELDS).is_none());
    }

    #[test]
    fn embedded_round_trips_and_matches_prost() {
        let limit = OrderLimit {
            serial_number: vec![2; 16],
            limit: 9,
            ..OrderLimit::default()
        };
        let order = Order {
            serial_number: vec![2; 16],
            amount: 9,
            uplink_signature: vec![7; 64],
        };
        let request = SettlementRequest {
            limit: Some(limit.clone()),
            order: Some(order.clone()),
        };
        let mut by_hand = Vec::new();
        put_embedded(&mut by_hand, 1, &limit.encode_to_vec());
        put_embedded(&mut by_hand, 2, &order.encode_to_vec());
        assert_eq!(by_hand, request.encode_to_vec());
        assert_eq!(embedded(&by_hand, 1).unwrap(), limit.encode_to_vec());
        assert_eq!(embedded(&by_hand, 2).unwrap(), order.encode_to_vec());
        assert!(embedded(&by_hand, 3).is_none());

        // Twice is ambiguous: protobuf would merge the two.
        let mut twice = by_hand.clone();
        put_embedded(&mut twice, 1, b"");
        assert!(embedded(&twice, 1).is_none());

        // A long value needs a two-byte length.
        let long = vec![9u8; 300];
        let mut out = Vec::new();
        put_embedded(&mut out, 3, &long);
        assert_eq!(embedded(&out, 3).unwrap(), long.as_slice());
    }
}
