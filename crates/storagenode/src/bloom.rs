//! Piece bloom filter from `storj/shared/bloomfilter/filter.go`.
//!
//! Wire bytes are version `1`, seed, hash count, then the table. A piece id
//! is 32 bytes, copied twice into a 64-byte buffer. `fastdiv` is only a speed
//! trick in Go; the bucket is plain `hash % table_len`.

use std::fmt;

const VERSION: u8 = 1;
/// Offsets that keep the first hashes from landing on the same bytes.
const RANGE_OFFSETS: [u8; 4] = [9, 13, 19, 23];

/// Why [`Filter::from_bytes`] rejected a buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterError {
    /// Fewer than the version, seed, and hash-count bytes.
    Short,
    /// Version byte was not 1.
    Version(u8),
    /// Hash count was 0. Every piece would match.
    HashCount,
    /// Table length was 0. Go panics in `fastdiv` on that divisor, and an
    /// empty table would trash every older piece.
    Empty,
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Short => f.write_str("not enough data"),
            Self::Version(version) => write!(f, "unsupported version {version}"),
            Self::HashCount => f.write_str("invalid hash count 0"),
            Self::Empty => f.write_str("empty bloom table"),
        }
    }
}

impl std::error::Error for FilterError {}

/// Bloom filter of piece ids a satellite wants kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Filter {
    /// Wire seed. Membership uses `offset`, which is derived from this.
    #[allow(dead_code)]
    seed: u8,
    hash_count: u8,
    table: Vec<u8>,
    offset: u8,
    range_offset: u8,
}

impl Filter {
    /// Decodes the wire format. The table is copied.
    pub fn from_bytes(data: &[u8]) -> Result<Self, FilterError> {
        if data.len() < 3 {
            return Err(FilterError::Short);
        }
        if data[0] != VERSION {
            return Err(FilterError::Version(data[0]));
        }
        let hash_count = data[2];
        if hash_count == 0 {
            return Err(FilterError::HashCount);
        }
        if data.len() == 3 {
            return Err(FilterError::Empty);
        }
        let seed = data[1];
        let (offset, range_offset) = initial_conditions(seed);
        Ok(Self {
            seed,
            hash_count,
            table: data[3..].to_vec(),
            offset,
            range_offset,
        })
    }

    /// True when every hash lands on a set bit.
    ///
    /// A miss means the piece is not in the set. A hit can be a false positive.
    pub fn contains(&self, piece_id: &[u8; 32]) -> bool {
        let table = &self.table;
        visit_hashes(
            piece_id,
            self.offset,
            self.range_offset,
            self.hash_count,
            table.len(),
            |bucket, bit| table[bucket] & (1u8 << bit) != 0,
        )
    }

    /// `seed` is the wire seed. `hash_count` must be non-zero and `bytes` the table length.
    #[cfg(test)]
    pub(crate) fn new(seed: u8, hash_count: u8, bytes: usize) -> Result<Self, FilterError> {
        if hash_count == 0 {
            return Err(FilterError::HashCount);
        }
        if bytes == 0 {
            return Err(FilterError::Empty);
        }
        let (offset, range_offset) = initial_conditions(seed);
        Ok(Self {
            seed,
            hash_count,
            table: vec![0; bytes],
            offset,
            range_offset,
        })
    }

    /// Sets the bits for `piece_id`.
    #[cfg(test)]
    pub(crate) fn add(&mut self, piece_id: &[u8; 32]) {
        let table = &mut self.table;
        let _ = visit_hashes(
            piece_id,
            self.offset,
            self.range_offset,
            self.hash_count,
            table.len(),
            |bucket, bit| {
                table[bucket] |= 1u8 << bit;
                true
            },
        );
    }

    /// Version, seed, hash count, then the table.
    #[cfg(test)]
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(3 + self.table.len());
        bytes.push(VERSION);
        bytes.push(self.seed);
        bytes.push(self.hash_count);
        bytes.extend_from_slice(&self.table);
        bytes
    }
}

fn initial_conditions(seed: u8) -> (u8, u8) {
    let offset = seed % 32;
    let range_offset = RANGE_OFFSETS[usize::from(seed / 32) % RANGE_OFFSETS.len()];
    (offset, range_offset)
}

/// Walks the `hash_count` positions. `bit` is already `bit % 8`.
///
/// Returns false when `f` does, or when the table is empty. An empty table has
/// no bucket: `% 0` is not a hash.
fn visit_hashes(
    piece_id: &[u8; 32],
    offset: u8,
    range_offset: u8,
    hash_count: u8,
    table_len: usize,
    mut f: impl FnMut(usize, u8) -> bool,
) -> bool {
    let Some(table_len) = u64::try_from(table_len).ok().filter(|len| *len > 0) else {
        return false;
    };
    let mut id = [0u8; 64];
    id[..32].copy_from_slice(piece_id);
    id[32..].copy_from_slice(piece_id);
    let mut offset = usize::from(offset);
    let step = usize::from(range_offset);
    for _ in 0..hash_count {
        let mut hash_bytes = [0u8; 8];
        hash_bytes.copy_from_slice(&id[offset..offset + 8]);
        let hash = u64::from_le_bytes(hash_bytes);
        let bit = id[offset + 8] % 8;
        let bucket = usize::try_from(hash % table_len).expect("bucket fits the table");
        if !f(bucket, bit) {
            return false;
        }
        offset = (offset + step) % 32;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{Filter, FilterError};

    #[test]
    fn rejects_short_bad_version_zero_hash_count_and_empty_table() {
        assert_eq!(Filter::from_bytes(&[]).unwrap_err(), FilterError::Short);
        assert_eq!(Filter::from_bytes(&[0]).unwrap_err(), FilterError::Short);
        assert_eq!(Filter::from_bytes(&[1]).unwrap_err(), FilterError::Short);
        assert_eq!(Filter::from_bytes(&[1, 0]).unwrap_err(), FilterError::Short);
        assert_eq!(
            Filter::from_bytes(&[255, 10, 10, 10]).unwrap_err(),
            FilterError::Version(255)
        );
        assert_eq!(
            Filter::from_bytes(&[1, 9, 0]).unwrap_err(),
            FilterError::HashCount
        );
        assert_eq!(
            Filter::from_bytes(&[1, 9, 0, 0xff]).unwrap_err(),
            FilterError::HashCount
        );
        assert_eq!(
            Filter::from_bytes(&[1, 4, 1]).unwrap_err(),
            FilterError::Empty
        );
        assert_eq!(Filter::new(1, 0, 8).unwrap_err(), FilterError::HashCount);
        assert_eq!(Filter::new(1, 1, 0).unwrap_err(), FilterError::Empty);
    }

    #[test]
    fn hand_built_filter_matches_the_go_bit_formula() {
        // seed 0 => offset 0, rangeOffset 9. piece 0x01 * 32.
        // hash = le u64 at 0 = 0x0101010101010101, bucket = hash % 8 = 1,
        // next byte 0x01, bit = 1, so table[1] has bit 1.
        let bytes = [1, 0, 1, 0, 0x02, 0, 0, 0, 0, 0, 0];
        let filter = Filter::from_bytes(&bytes).unwrap();
        assert!(filter.contains(&[0x01; 32]));
        assert!(!filter.contains(&[0x02; 32]));

        let mut built = Filter::new(0, 1, 8).unwrap();
        built.add(&[0x01; 32]);
        assert_eq!(built.to_bytes(), bytes);
        assert!(built.contains(&[0x01; 32]));
        assert!(!built.contains(&[0x02; 32]));
    }

    #[test]
    fn go_golden_vector_round_trips() {
        // `TestGolden` in storj/shared/bloomfilter/filter_test.go.
        // NewExplicit(153, 3, 256) plus these five piece ids.
        let ids: [[u8; 32]; 5] = [
            [
                0x52, 0xfd, 0xfc, 0x07, 0x21, 0x82, 0x65, 0x4f, 0x16, 0x3f, 0x5f, 0x0f, 0x9a, 0x62,
                0x1d, 0x72, 0x95, 0x66, 0xc7, 0x4d, 0x10, 0x03, 0x7c, 0x4d, 0x7b, 0xbb, 0x04, 0x07,
                0xd1, 0xe2, 0xc6, 0x49,
            ],
            [
                0x81, 0x85, 0x5a, 0xd8, 0x68, 0x1d, 0x0d, 0x86, 0xd1, 0xe9, 0x1e, 0x00, 0x16, 0x79,
                0x39, 0xcb, 0x66, 0x94, 0xd2, 0xc4, 0x22, 0xac, 0xd2, 0x08, 0xa0, 0x07, 0x29, 0x39,
                0x48, 0x7f, 0x69, 0x99,
            ],
            [
                0xeb, 0x9d, 0x18, 0xa4, 0x47, 0x84, 0x04, 0x5d, 0x87, 0xf3, 0xc6, 0x7c, 0xf2, 0x27,
                0x46, 0xe9, 0x95, 0xaf, 0x5a, 0x25, 0x36, 0x79, 0x51, 0xba, 0xa2, 0xff, 0x6c, 0xd4,
                0x71, 0xc4, 0x83, 0xf1,
            ],
            [
                0x5f, 0xb9, 0x0b, 0xad, 0xb3, 0x7c, 0x58, 0x21, 0xb6, 0xd9, 0x55, 0x26, 0xa4, 0x1a,
                0x95, 0x04, 0x68, 0x0b, 0x4e, 0x7c, 0x8b, 0x76, 0x3a, 0x1b, 0x1d, 0x49, 0xd4, 0x95,
                0x5c, 0x84, 0x86, 0x21,
            ],
            [
                0x63, 0x25, 0x25, 0x3f, 0xec, 0x73, 0x8d, 0xd7, 0xa9, 0xe2, 0x8b, 0xf9, 0x21, 0x11,
                0x9c, 0x16, 0x0f, 0x07, 0x02, 0x44, 0x86, 0x15, 0xbb, 0xda, 0x08, 0x31, 0x3f, 0x6a,
                0x8e, 0xb6, 0x68, 0xd2,
            ],
        ];
        let expected: [u8; 259] = [
            0x01, 0x99, 0x03, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
            0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x10,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x10, 0x00, 0x00, 0x80, 0x00, 0x00, 0x20,
        ];
        let decoded = Filter::from_bytes(&expected).unwrap();
        for id in &ids {
            assert!(decoded.contains(id));
        }
        let mut filter = Filter::new(153, 3, 256).unwrap();
        for id in &ids {
            filter.add(id);
        }
        assert_eq!(filter.to_bytes(), expected);
        for id in &ids {
            assert!(filter.contains(id));
        }
        assert!(!filter.contains(&[0; 32]));
    }
}
