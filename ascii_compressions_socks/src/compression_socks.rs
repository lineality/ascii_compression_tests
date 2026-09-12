//! ============================================================================
//! File Path: /src/compression_socks.rs
//! Project: Safety-Critical UDP ASCII Text Compression Framework
//! Development Phase: Production-Release (Long-Term Core Subsystem)
//! Context: Low-latency, fixed 128-byte MTU payload comparison engine comparing:
//!          1. Uniform 7-Bit Packing
//!          2. Canonical Static Huffman Coding (Compile-Time Frequency Tree)
//!          3. 8th-Bit Micro-Dictionary Tokenization
//! ============================================================================

#![forbid(unsafe_code)]

/// Maximum allowed payload size for standard UDP datagram compression blocks.
pub const CC_MAX_BLOCK_CAPACITY: usize = 128;

/// Error taxonomy implemented as a 2-byte fieldless enum.
/// Append-only enumeration; values are permanent and globally unique.
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CompressCompareError {
    // 1000..1099: Enforced Custom Type & Boundary Errors
    CcBlockNewInputTooLong = 1001,
    CcBlockNewNonAscii = 1002,
    CcBlockRecheckLengthExceeded = 1003,
    CcBlockRecheckNonAscii = 1004,
    CcBlockGetSliceFailed = 1005,

    // 1100..1199: 7-Bit Packing Subsystem Errors
    CcPack7BitOverflow = 1101,
    CcPack7BitMathOverflow = 1102,
    CcUnpack7BitTruncated = 1103,
    CcUnpack7BitNonAscii = 1104,
    CcUnpack7BitMathOverflow = 1105,

    // 1200..1299: Static Huffman Subsystem Errors
    CcHuffmanEncodeOverflow = 1201,
    CcHuffmanEncodeMathOverflow = 1202,
    CcHuffmanDecodeTruncated = 1203,
    CcHuffmanDecodeBitOverflow = 1204,
    CcHuffmanDecodeTreeCorrupt = 1205,

    // 1300..1399: 8th-Bit Tokenization Subsystem Errors
    CcTokenizeEncodeOverflow = 1301,
    CcTokenizeEncodeMathOverflow = 1302,
    CcTokenizeDecodeInvalidToken = 1303,
    CcTokenizeDecodeOverflow = 1304,
    CcTokenizeDecodeMathOverflow = 1305,

    // 1400..1499: Verification & Test Harness Errors
    CcEvalSentenceMismatch = 1401,
    CcEvalSentenceEmpty = 1402,

    // 1500..1599: Driver / Supervisory Errors
    _CcDriverTransientBufferBusy = 1501,
    CcDriverSupervisoryUnrecoverable = 1502,

    // 1600..1699: Timing Harness Subsystem Errors
    CcTimingIterationsZero = 1601,
    CcTimingIterationsTooLarge = 1602,
    CcTimingIterationCountCorrupt = 1603,
    CcTimingDurationOverflow = 1604,
    CcTimingDivisionByZero = 1605,
    CcTimingIndexOutOfRange = 1606,
    CcTimingLoopCounterOverflow = 1607,
    CcTimingUnexpectedBlockLength = 1608,
}

impl CompressCompareError {
    /// Exhaustive mapping of retryability for Tier-1 local micro-retries.
    /// In accordance with framework rules: deterministic buffer/data corruption
    /// fails immediately to Tier-2 fallback; transient states yield true.
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::_CcDriverTransientBufferBusy => true,

            Self::CcBlockNewInputTooLong
            | Self::CcBlockNewNonAscii
            | Self::CcBlockRecheckLengthExceeded
            | Self::CcBlockRecheckNonAscii
            | Self::CcBlockGetSliceFailed
            | Self::CcPack7BitOverflow
            | Self::CcPack7BitMathOverflow
            | Self::CcUnpack7BitTruncated
            | Self::CcUnpack7BitNonAscii
            | Self::CcUnpack7BitMathOverflow
            | Self::CcHuffmanEncodeOverflow
            | Self::CcHuffmanEncodeMathOverflow
            | Self::CcHuffmanDecodeTruncated
            | Self::CcHuffmanDecodeBitOverflow
            | Self::CcHuffmanDecodeTreeCorrupt
            | Self::CcTokenizeEncodeOverflow
            | Self::CcTokenizeEncodeMathOverflow
            | Self::CcTokenizeDecodeInvalidToken
            | Self::CcTokenizeDecodeOverflow
            | Self::CcTokenizeDecodeMathOverflow
            | Self::CcEvalSentenceMismatch
            | Self::CcDriverSupervisoryUnrecoverable
            | Self::CcTimingIterationsZero
            | Self::CcTimingIterationsTooLarge
            | Self::CcTimingIterationCountCorrupt
            | Self::CcTimingDurationOverflow
            | Self::CcTimingDivisionByZero
            | Self::CcTimingIndexOutOfRange
            | Self::CcTimingLoopCounterOverflow
            | Self::CcTimingUnexpectedBlockLength
            | Self::CcEvalSentenceEmpty => false,
        }
    }
}

#[cfg(debug_assertions)]
impl core::fmt::Display for CompressCompareError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CompressCompareError Code: {}", *self as u16)
    }
}

/// Enforced Custom Type: Guarantees memory invariants for a bounded ASCII block.
/// Storage is strictly stack-allocated; internal state is private to prevent bypass.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CompressCompareAsciiBlock128 {
    block_bytes: [u8; CC_MAX_BLOCK_CAPACITY],
    block_length: u8,
}

impl CompressCompareAsciiBlock128 {
    /// Constructs and validates a new `CompressCompareAsciiBlock128`.
    pub fn new(input_slice: &[u8]) -> Result<Self, CompressCompareError> {
        if input_slice.len() > CC_MAX_BLOCK_CAPACITY {
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(false, "Invariant Violated: input length > 128");
            #[cfg(debug_assertions)]
            eprintln!("CC-1001: input length exceeds CC_MAX_BLOCK_CAPACITY");
            return Err(CompressCompareError::CcBlockNewInputTooLong);
        }

        let mut storage = [0u8; CC_MAX_BLOCK_CAPACITY];
        let mut write_cursor: usize = 0;

        while write_cursor < input_slice.len() {
            let byte_value = match input_slice.get(write_cursor) {
                Some(&val) => val,
                None => {
                    #[cfg(all(debug_assertions, not(test)))]
                    debug_assert!(false, "Invariant Violated: slice index out of bounds");
                    #[cfg(debug_assertions)]
                    eprintln!("CC-1005: slice access failed during block construction");
                    return Err(CompressCompareError::CcBlockGetSliceFailed);
                }
            };

            // ASCII verification invariant: bit 7 must be zero
            if byte_value > 127 {
                #[cfg(all(debug_assertions, not(test)))]
                debug_assert!(false, "Invariant Violated: non-ASCII byte detected");
                #[cfg(debug_assertions)]
                eprintln!("CC-1002: non-ASCII character byte: {:#X}", byte_value);
                return Err(CompressCompareError::CcBlockNewNonAscii);
            }

            storage[write_cursor] = byte_value;
            write_cursor = match write_cursor.checked_add(1) {
                Some(next_idx) => next_idx,
                None => {
                    #[cfg(all(debug_assertions, not(test)))]
                    debug_assert!(false, "Invariant Violated: cursor increment overflow");
                    #[cfg(debug_assertions)]
                    eprintln!("CC-1003: write cursor math overflow");
                    return Err(CompressCompareError::CcBlockRecheckLengthExceeded);
                }
            };
        }

        Ok(Self {
            block_bytes: storage,
            block_length: input_slice.len() as u8,
        })
    }

    /// Explicit validity re-check method to guard against hardware corruption and bit-flips.
    pub fn validity_recheck(&self) -> Result<(), CompressCompareError> {
        let length_usize = self.block_length as usize;
        if length_usize > CC_MAX_BLOCK_CAPACITY {
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(false, "Invariant Violated: internal block_length corrupted");
            #[cfg(debug_assertions)]
            eprintln!("CC-1003: recheck failed, length: {}", length_usize);
            return Err(CompressCompareError::CcBlockRecheckLengthExceeded);
        }

        let mut verify_idx: usize = 0;
        while verify_idx < length_usize {
            match self.block_bytes.get(verify_idx) {
                Some(&byte) => {
                    if byte > 127 {
                        #[cfg(all(debug_assertions, not(test)))]
                        debug_assert!(false, "Invariant Violated: corrupted non-ASCII in storage");
                        #[cfg(debug_assertions)]
                        eprintln!("CC-1004: recheck failed, byte: {:#X}", byte);
                        return Err(CompressCompareError::CcBlockRecheckNonAscii);
                    }
                }
                None => {
                    #[cfg(all(debug_assertions, not(test)))]
                    debug_assert!(
                        false,
                        "Invariant Violated: storage bounds error during recheck"
                    );
                    #[cfg(debug_assertions)]
                    eprintln!("CC-1005: storage get failed during recheck");
                    return Err(CompressCompareError::CcBlockGetSliceFailed);
                }
            }

            verify_idx = match verify_idx.checked_add(1) {
                Some(next_idx) => next_idx,
                None => return Err(CompressCompareError::CcBlockRecheckLengthExceeded),
            };
        }

        Ok(())
    }

    /// Accessor returning a slice to the verified internal data.
    /// Performs a mandatory validity recheck before yielding data.
    pub fn get(&self) -> Result<&[u8], CompressCompareError> {
        match self.validity_recheck() {
            Ok(()) => (),
            Err(err_code) => return Err(err_code),
        }

        match self.block_bytes.get(..self.block_length as usize) {
            Some(slice) => Ok(slice),
            None => {
                #[cfg(all(debug_assertions, not(test)))]
                debug_assert!(
                    false,
                    "Invariant Violated: get(..len) failed after successful recheck"
                );
                #[cfg(debug_assertions)]
                eprintln!("CC-1005: slice extraction failed");
                Err(CompressCompareError::CcBlockGetSliceFailed)
            }
        }
    }

    /// Returns the length of the ASCII payload in bytes.
    pub fn len(&self) -> u8 {
        self.block_length
    }

    /// Checks if the payload contains zero bytes.
    pub fn is_empty(&self) -> bool {
        self.block_length == 0
    }
}

/// Enforced Custom Type: Bounded stack-only storage for compressed output.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CompressCompareCompressedBlock128 {
    payload_bytes: [u8; CC_MAX_BLOCK_CAPACITY],
    payload_length: u8,
    original_length: u8,
}

impl CompressCompareCompressedBlock128 {
    pub const fn empty() -> Self {
        Self {
            payload_bytes: [0u8; CC_MAX_BLOCK_CAPACITY],
            payload_length: 0,
            original_length: 0,
        }
    }

    /// Internal boundary integrity check for compressed block state.
    pub fn validity_recheck(&self) -> Result<(), CompressCompareError> {
        let len_usize = self.payload_length as usize;
        let orig_usize = self.original_length as usize;

        if len_usize > CC_MAX_BLOCK_CAPACITY || orig_usize > CC_MAX_BLOCK_CAPACITY {
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(
                false,
                "Invariant Violated: compressed block length exceeds CC_MAX_BLOCK_CAPACITY"
            );
            #[cfg(debug_assertions)]
            eprintln!(
                "CC-1003: compressed block corrupted (payload_len={}, orig_len={})",
                len_usize, orig_usize
            );
            return Err(CompressCompareError::CcBlockRecheckLengthExceeded);
        }

        Ok(())
    }

    /// Accessor returning the verified byte slice intended for UDP transmission.
    pub fn payload_slice(&self) -> Result<&[u8], CompressCompareError> {
        match self.validity_recheck() {
            Ok(()) => (),
            Err(err) => return Err(err),
        }

        let len_usize = self.payload_length as usize;
        match self.payload_bytes.get(..len_usize) {
            Some(slice) => Ok(slice),
            None => {
                #[cfg(all(debug_assertions, not(test)))]
                debug_assert!(
                    false,
                    "Invariant Violated: payload_bytes slice extraction failed"
                );
                #[cfg(debug_assertions)]
                eprintln!("CC-1005: slice access failed in payload_slice");
                Err(CompressCompareError::CcBlockGetSliceFailed)
            }
        }
    }

    pub fn length(&self) -> u8 {
        self.payload_length
    }

    pub fn original_length(&self) -> u8 {
        self.original_length
    }
}

// -----------------------------------------------------------------------------
// ALGORITHM 1: 7-Bit Packing Implementation
// -----------------------------------------------------------------------------

/// Packs verified 7-bit ASCII characters tightly into bytes without highest bit waste.
pub fn compress_compare_pack_7bit(
    input_block: &CompressCompareAsciiBlock128,
) -> Result<CompressCompareCompressedBlock128, CompressCompareError> {
    let raw_slice = match input_block.get() {
        Ok(s) => s,
        Err(e) => return Err(e),
    };

    let mut output = CompressCompareCompressedBlock128::empty();
    output.original_length = input_block.len();

    let mut bit_cursor: usize = 0;
    let mut char_idx: usize = 0;

    while char_idx < raw_slice.len() {
        let ascii_value = raw_slice[char_idx] as u16;
        let mut bit_step: usize = 0;

        while bit_step < 7 {
            let bit_is_set = ((ascii_value >> bit_step) & 1) == 1;
            let byte_index = bit_cursor
                .checked_div(8)
                .ok_or(CompressCompareError::CcPack7BitMathOverflow)?;
            let bit_in_byte = bit_cursor % 8;

            if byte_index >= CC_MAX_BLOCK_CAPACITY {
                #[cfg(debug_assertions)]
                eprintln!("CC-1101: 7-bit pack exceeded byte capacity");
                return Err(CompressCompareError::CcPack7BitOverflow);
            }

            if bit_is_set {
                output.payload_bytes[byte_index] |= 1 << bit_in_byte;
            }

            bit_cursor = match bit_cursor.checked_add(1) {
                Some(next_val) => next_val,
                None => return Err(CompressCompareError::CcPack7BitMathOverflow),
            };

            bit_step = match bit_step.checked_add(1) {
                Some(next_step) => next_step,
                None => return Err(CompressCompareError::CcPack7BitMathOverflow),
            };
        }

        char_idx = match char_idx.checked_add(1) {
            Some(next_idx) => next_idx,
            None => return Err(CompressCompareError::CcPack7BitMathOverflow),
        };
    }

    let rounded_bits = match bit_cursor.checked_add(7) {
        Some(val) => val,
        None => return Err(CompressCompareError::CcPack7BitMathOverflow),
    };
    let total_bytes = rounded_bits
        .checked_div(8)
        .ok_or(CompressCompareError::CcPack7BitMathOverflow)?;

    if total_bytes > CC_MAX_BLOCK_CAPACITY {
        return Err(CompressCompareError::CcPack7BitOverflow);
    }

    output.payload_length = total_bytes as u8;
    Ok(output)
}

// --- In compress_compare_unpack_7bit ---
pub fn compress_compare_unpack_7bit(
    compressed_block: &CompressCompareCompressedBlock128,
) -> Result<CompressCompareAsciiBlock128, CompressCompareError> {
    let payload = match compressed_block.payload_slice() {
        Ok(slice) => slice,
        Err(err) => return Err(err),
    };
    let mut intermediate_buffer = [0u8; CC_MAX_BLOCK_CAPACITY];
    let expected_len = compressed_block.original_length() as usize;

    if expected_len > CC_MAX_BLOCK_CAPACITY {
        #[cfg(debug_assertions)]
        eprintln!("CC-1103: target length > capacity during 7-bit unpack");
        return Err(CompressCompareError::CcUnpack7BitTruncated);
    }

    let mut bit_cursor: usize = 0;
    let mut char_idx: usize = 0;

    while char_idx < expected_len {
        let mut reconstructed_char: u8 = 0;
        let mut bit_step: usize = 0;

        while bit_step < 7 {
            let byte_index = bit_cursor
                .checked_div(8)
                .ok_or(CompressCompareError::CcUnpack7BitMathOverflow)?;
            let bit_in_byte = bit_cursor % 8;

            let byte_val = match payload.get(byte_index) {
                Some(&b) => b,
                None => {
                    #[cfg(debug_assertions)]
                    eprintln!("CC-1103: unexpected EOF reading 7-bit stream");
                    return Err(CompressCompareError::CcUnpack7BitTruncated);
                }
            };

            let bit_val = (byte_val >> bit_in_byte) & 1;
            reconstructed_char |= bit_val << bit_step;

            bit_cursor = match bit_cursor.checked_add(1) {
                Some(next_val) => next_val,
                None => return Err(CompressCompareError::CcUnpack7BitMathOverflow),
            };

            bit_step = match bit_step.checked_add(1) {
                Some(next_step) => next_step,
                None => return Err(CompressCompareError::CcUnpack7BitMathOverflow),
            };
        }

        if reconstructed_char > 127 {
            #[cfg(debug_assertions)]
            eprintln!(
                "CC-1104: unpacked byte exceeds ASCII limit: {:#X}",
                reconstructed_char
            );
            return Err(CompressCompareError::CcUnpack7BitNonAscii);
        }

        intermediate_buffer[char_idx] = reconstructed_char;
        char_idx = match char_idx.checked_add(1) {
            Some(next_idx) => next_idx,
            None => return Err(CompressCompareError::CcUnpack7BitMathOverflow),
        };
    }

    CompressCompareAsciiBlock128::new(&intermediate_buffer[..expected_len])
}

// --- In compress_compare_huffman_decode ---
pub fn compress_compare_huffman_decode(
    compressed_block: &CompressCompareCompressedBlock128,
) -> Result<CompressCompareAsciiBlock128, CompressCompareError> {
    let payload = match compressed_block.payload_slice() {
        Ok(slice) => slice,
        Err(err) => return Err(err),
    };
    let (_, decode_tree) = &STATIC_HUFFMAN_CODEC;
    let mut intermediate_buffer = [0u8; CC_MAX_BLOCK_CAPACITY];
    let target_length = compressed_block.original_length() as usize;

    if target_length > CC_MAX_BLOCK_CAPACITY {
        #[cfg(debug_assertions)]
        eprintln!("CC-1203: target length exceeds CC_MAX_BLOCK_CAPACITY");
        return Err(CompressCompareError::CcHuffmanDecodeTruncated);
    }

    let mut bit_cursor: usize = 0;
    let mut decoded_count: usize = 0;
    let total_bits = (payload.len())
        .checked_mul(8)
        .ok_or(CompressCompareError::CcHuffmanDecodeBitOverflow)?;

    while decoded_count < target_length {
        let mut current_node: u8 = 254; // Root node index

        while current_node >= 128 {
            if bit_cursor >= total_bits {
                #[cfg(debug_assertions)]
                eprintln!("CC-1203: unexpected bitstream exhaustion");
                return Err(CompressCompareError::CcHuffmanDecodeTruncated);
            }

            let byte_idx = bit_cursor
                .checked_div(8)
                .ok_or(CompressCompareError::CcHuffmanDecodeBitOverflow)?;
            let bit_in_byte = bit_cursor % 8;

            let byte_val = match payload.get(byte_idx) {
                Some(&b) => b,
                None => return Err(CompressCompareError::CcHuffmanDecodeTruncated),
            };
            let bit_is_set = ((byte_val >> bit_in_byte) & 1) == 1;

            let internal_idx = (current_node - 128) as usize;
            let branch = match decode_tree.get(internal_idx) {
                Some(nodes) => nodes,
                None => return Err(CompressCompareError::CcHuffmanDecodeTreeCorrupt),
            };

            current_node = if !bit_is_set { branch.0 } else { branch.1 };

            bit_cursor = match bit_cursor.checked_add(1) {
                Some(next_val) => next_val,
                None => return Err(CompressCompareError::CcHuffmanDecodeBitOverflow),
            };
        }

        intermediate_buffer[decoded_count] = current_node;
        decoded_count = match decoded_count.checked_add(1) {
            Some(next_cnt) => next_cnt,
            None => return Err(CompressCompareError::CcHuffmanDecodeBitOverflow),
        };
    }

    CompressCompareAsciiBlock128::new(&intermediate_buffer[..target_length])
}

// -----------------------------------------------------------------------------
// ALGORITHM 2: Canonical Static Huffman (Compile-Time .rodata Construction)
// -----------------------------------------------------------------------------

#[derive(Copy, Clone)]
struct HuffmanConstructionNode {
    weight: u32,
    parent_index: u8,
    left_child: u8,
    right_child: u8,
    is_active: bool,
}

/// Pure `const fn` computing optimal prefix codes and decode graphs at compile time.
const fn build_compile_time_huffman_codec() -> ([(u16, u8); 128], [(u8, u8); 127]) {
    let mut weights = [1u32; 128];

    // Static English & ASCII frequency priors
    weights[b' ' as usize] = 310;
    weights[b'e' as usize] = 210;
    weights[b't' as usize] = 165;
    weights[b'a' as usize] = 145;
    weights[b'o' as usize] = 135;
    weights[b'i' as usize] = 125;
    weights[b'n' as usize] = 125;
    weights[b's' as usize] = 115;
    weights[b'r' as usize] = 105;
    weights[b'h' as usize] = 95;
    weights[b'l' as usize] = 75;
    weights[b'd' as usize] = 70;
    weights[b'c' as usize] = 65;
    weights[b'u' as usize] = 60;
    weights[b'm' as usize] = 55;
    weights[b'f' as usize] = 50;
    weights[b'p' as usize] = 45;
    weights[b'g' as usize] = 40;
    weights[b'w' as usize] = 35;
    weights[b'y' as usize] = 35;
    weights[b'b' as usize] = 30;
    weights[b',' as usize] = 45;
    weights[b'.' as usize] = 45;
    weights[b':' as usize] = 25;
    weights[b'\'' as usize] = 25;

    let mut nodes = [HuffmanConstructionNode {
        weight: 0,
        parent_index: 255,
        left_child: 255,
        right_child: 255,
        is_active: false,
    }; 255];

    let mut leaf_idx = 0;
    while leaf_idx < 128 {
        nodes[leaf_idx] = HuffmanConstructionNode {
            weight: weights[leaf_idx],
            parent_index: 255,
            left_child: 255,
            right_child: 255,
            is_active: true,
        };
        leaf_idx += 1;
    }

    let mut internal_cursor = 128;
    while internal_cursor < 255 {
        let mut min1 = 255usize;
        let mut min2 = 255usize;

        let mut scan_idx = 0;
        while scan_idx < internal_cursor {
            if nodes[scan_idx].is_active {
                if min1 == 255 || nodes[scan_idx].weight < nodes[min1].weight {
                    min2 = min1;
                    min1 = scan_idx;
                } else if min2 == 255 || nodes[scan_idx].weight < nodes[min2].weight {
                    min2 = scan_idx;
                }
            }
            scan_idx += 1;
        }

        nodes[min1].is_active = false;
        nodes[min2].is_active = false;
        nodes[min1].parent_index = internal_cursor as u8;
        nodes[min2].parent_index = internal_cursor as u8;

        nodes[internal_cursor] = HuffmanConstructionNode {
            weight: nodes[min1].weight + nodes[min2].weight,
            parent_index: 255,
            left_child: min1 as u8,
            right_child: min2 as u8,
            is_active: true,
        };

        internal_cursor += 1;
    }

    let mut codes = [(0u16, 0u8); 128];
    let mut sym_idx = 0;
    while sym_idx < 128 {
        let mut walk = sym_idx;
        let mut raw_code = 0u16;
        let mut bit_depth = 0u8;

        while walk != 254 {
            let parent = nodes[walk].parent_index as usize;
            let is_right_branch = nodes[parent].right_child == (walk as u8);
            if is_right_branch {
                raw_code |= 1 << bit_depth;
            }
            bit_depth += 1;
            walk = parent;
        }

        // Reverse code to allow sequential traversal from root downwards
        let mut reversed_code = 0u16;
        let mut rev_idx = 0u8;
        while rev_idx < bit_depth {
            if (raw_code & (1 << (bit_depth - 1 - rev_idx))) != 0 {
                reversed_code |= 1 << rev_idx;
            }
            rev_idx += 1;
        }

        codes[sym_idx] = (reversed_code, bit_depth);
        sym_idx += 1;
    }

    let mut decode_tree = [(0u8, 0u8); 127];
    let mut tree_idx = 0;
    while tree_idx < 127 {
        decode_tree[tree_idx] = (
            nodes[128 + tree_idx].left_child,
            nodes[128 + tree_idx].right_child,
        );
        tree_idx += 1;
    }

    (codes, decode_tree)
}

static STATIC_HUFFMAN_CODEC: ([(u16, u8); 128], [(u8, u8); 127]) =
    build_compile_time_huffman_codec();

/// Compresses an ASCII block using canonical static Huffman codes.
pub fn compress_compare_huffman_encode(
    input_block: &CompressCompareAsciiBlock128,
) -> Result<CompressCompareCompressedBlock128, CompressCompareError> {
    let raw_slice = match input_block.get() {
        Ok(s) => s,
        Err(e) => return Err(e),
    };

    let mut output = CompressCompareCompressedBlock128::empty();
    output.original_length = input_block.len();

    let (codes, _) = &STATIC_HUFFMAN_CODEC;
    let mut bit_cursor: usize = 0;
    let mut char_idx: usize = 0;

    while char_idx < raw_slice.len() {
        let ascii_byte = raw_slice[char_idx] as usize;
        let (code, bit_length) = codes[ascii_byte];
        let mut step: u8 = 0;

        while step < bit_length {
            let bit_is_set = ((code >> step) & 1) == 1;
            let byte_index = bit_cursor
                .checked_div(8)
                .ok_or(CompressCompareError::CcHuffmanEncodeMathOverflow)?;
            let bit_in_byte = bit_cursor % 8;

            if byte_index >= CC_MAX_BLOCK_CAPACITY {
                #[cfg(debug_assertions)]
                eprintln!("CC-1201: huffman bitstream exceeded output capacity");
                return Err(CompressCompareError::CcHuffmanEncodeOverflow);
            }

            if bit_is_set {
                output.payload_bytes[byte_index] |= 1 << bit_in_byte;
            }

            bit_cursor = match bit_cursor.checked_add(1) {
                Some(next_val) => next_val,
                None => return Err(CompressCompareError::CcHuffmanEncodeMathOverflow),
            };

            step = match step.checked_add(1) {
                Some(next_step) => next_step,
                None => return Err(CompressCompareError::CcHuffmanEncodeMathOverflow),
            };
        }

        char_idx = match char_idx.checked_add(1) {
            Some(next_idx) => next_idx,
            None => return Err(CompressCompareError::CcHuffmanEncodeMathOverflow),
        };
    }

    let rounded_bits = match bit_cursor.checked_add(7) {
        Some(val) => val,
        None => return Err(CompressCompareError::CcHuffmanEncodeMathOverflow),
    };
    let total_bytes = rounded_bits
        .checked_div(8)
        .ok_or(CompressCompareError::CcHuffmanEncodeMathOverflow)?;

    if total_bytes > CC_MAX_BLOCK_CAPACITY {
        return Err(CompressCompareError::CcHuffmanEncodeOverflow);
    }

    output.payload_length = total_bytes as u8;
    Ok(output)
}

// -----------------------------------------------------------------------------
// ALGORITHM 3: 8th-Bit Micro-Dictionary Tokenization
// -----------------------------------------------------------------------------

/// Common English and UDP telemetry phrases mapped to values 128..255.
pub const CC_TOKEN_DICTIONARY: &[&[u8]] = &[
    b"the ", b"ing ", b"that", b"with", b"for ", b"and ", b"tion", b"this", b"th", b"he", b"in",
    b"er", b"an", b"re", b"ed", b"on", b"es", b"st", b"en", b"at", b"to", b"nt", b"ha", b"nd",
    b"ou", b"ea", b"ng", b"as", b"or", b"ti", b"is", b"et", b"it", b"ar", b"te", b"se", b"hi",
    b"of", b"me", b"ne", b"le", b"ve", b"al", b"de", b"ro", b"li", b"co", b"ra", b"ch", b"ll",
    b"wa", b"be", b"ma", b"om", b"ur", b"ca", b"el", b"ta", b"ns", b"so", b"no", b"ly", b"lo",
    b"  ",
];

/// Encodes ASCII text by replacing matching tokens with single high-bit bytes.
pub fn compress_compare_tokenize_encode(
    input_block: &CompressCompareAsciiBlock128,
) -> Result<CompressCompareCompressedBlock128, CompressCompareError> {
    let raw_slice = match input_block.get() {
        Ok(s) => s,
        Err(e) => return Err(e),
    };

    let mut output = CompressCompareCompressedBlock128::empty();
    output.original_length = input_block.len();

    let mut read_cursor: usize = 0;
    let mut write_cursor: usize = 0;

    while read_cursor < raw_slice.len() {
        let mut matched_token_idx: Option<usize> = None;
        let mut dict_scan: usize = 0;

        while dict_scan < CC_TOKEN_DICTIONARY.len() {
            let candidate_token = CC_TOKEN_DICTIONARY[dict_scan];
            if raw_slice[read_cursor..].starts_with(candidate_token) {
                matched_token_idx = Some(dict_scan);
                break;
            }
            dict_scan = match dict_scan.checked_add(1) {
                Some(next_scan) => next_scan,
                None => return Err(CompressCompareError::CcTokenizeEncodeMathOverflow),
            };
        }

        if write_cursor >= CC_MAX_BLOCK_CAPACITY {
            #[cfg(debug_assertions)]
            eprintln!("CC-1301: tokenize write cursor exceeded buffer capacity");
            return Err(CompressCompareError::CcTokenizeEncodeOverflow);
        }

        if let Some(token_idx) = matched_token_idx {
            output.payload_bytes[write_cursor] = (128 + token_idx) as u8;
            write_cursor = match write_cursor.checked_add(1) {
                Some(next_w) => next_w,
                None => return Err(CompressCompareError::CcTokenizeEncodeMathOverflow),
            };
            read_cursor = match read_cursor.checked_add(CC_TOKEN_DICTIONARY[token_idx].len()) {
                Some(next_r) => next_r,
                None => return Err(CompressCompareError::CcTokenizeEncodeMathOverflow),
            };
        } else {
            output.payload_bytes[write_cursor] = raw_slice[read_cursor];
            write_cursor = match write_cursor.checked_add(1) {
                Some(next_w) => next_w,
                None => return Err(CompressCompareError::CcTokenizeEncodeMathOverflow),
            };
            read_cursor = match read_cursor.checked_add(1) {
                Some(next_r) => next_r,
                None => return Err(CompressCompareError::CcTokenizeEncodeMathOverflow),
            };
        }
    }

    output.payload_length = write_cursor as u8;
    Ok(output)
}

// --- In compress_compare_tokenize_decode ---
pub fn compress_compare_tokenize_decode(
    compressed_block: &CompressCompareCompressedBlock128,
) -> Result<CompressCompareAsciiBlock128, CompressCompareError> {
    let payload = match compressed_block.payload_slice() {
        Ok(slice) => slice,
        Err(err) => return Err(err),
    };
    let mut intermediate_buffer = [0u8; CC_MAX_BLOCK_CAPACITY];
    let mut write_cursor: usize = 0;
    let mut read_cursor: usize = 0;

    while read_cursor < payload.len() {
        let current_byte = match payload.get(read_cursor) {
            Some(&b) => b,
            None => return Err(CompressCompareError::CcTokenizeDecodeOverflow),
        };

        if current_byte < 128 {
            if write_cursor >= CC_MAX_BLOCK_CAPACITY {
                #[cfg(debug_assertions)]
                eprintln!("CC-1304: token decode output overflow on literal byte");
                return Err(CompressCompareError::CcTokenizeDecodeOverflow);
            }
            intermediate_buffer[write_cursor] = current_byte;
            write_cursor = match write_cursor.checked_add(1) {
                Some(next_w) => next_w,
                None => return Err(CompressCompareError::CcTokenizeDecodeMathOverflow),
            };
        } else {
            let token_index = (current_byte - 128) as usize;
            let token_slice = match CC_TOKEN_DICTIONARY.get(token_index) {
                Some(slice) => *slice,
                None => {
                    #[cfg(debug_assertions)]
                    eprintln!("CC-1303: corrupt token index: {}", token_index);
                    return Err(CompressCompareError::CcTokenizeDecodeInvalidToken);
                }
            };

            let mut token_byte_idx = 0;
            while token_byte_idx < token_slice.len() {
                if write_cursor >= CC_MAX_BLOCK_CAPACITY {
                    #[cfg(debug_assertions)]
                    eprintln!("CC-1304: token decode output overflow on expanded token");
                    return Err(CompressCompareError::CcTokenizeDecodeOverflow);
                }
                intermediate_buffer[write_cursor] = token_slice[token_byte_idx];
                write_cursor = match write_cursor.checked_add(1) {
                    Some(next_w) => next_w,
                    None => return Err(CompressCompareError::CcTokenizeDecodeMathOverflow),
                };
                token_byte_idx = match token_byte_idx.checked_add(1) {
                    Some(next_t) => next_t,
                    None => return Err(CompressCompareError::CcTokenizeDecodeMathOverflow),
                };
            }
        }

        read_cursor = match read_cursor.checked_add(1) {
            Some(next_r) => next_r,
            None => return Err(CompressCompareError::CcTokenizeDecodeMathOverflow),
        };
    }

    CompressCompareAsciiBlock128::new(&intermediate_buffer[..write_cursor])
}

// -----------------------------------------------------------------------------
// BENCHMARK EVALUATION UNIT
// -----------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CompressCompareBenchmarkMetrics {
    pub raw_bytes: u8,
    pub bitpack_bytes: u8,
    pub huffman_bytes: u8,
    pub tokenized_bytes: u8,
}

/// Evaluates all 3 algorithms, enforcing roundtrip identity without panics.
pub fn compress_compare_evaluate_sentence(
    raw_sentence: &[u8],
) -> Result<CompressCompareBenchmarkMetrics, CompressCompareError> {
    let input_block = match CompressCompareAsciiBlock128::new(raw_sentence) {
        Ok(block) => block,
        Err(err) => return Err(err),
    };

    if input_block.is_empty() {
        #[cfg(debug_assertions)]
        eprintln!("CC-1402: cannot benchmark an empty sentence block");
        return Err(CompressCompareError::CcEvalSentenceEmpty);
    }

    // 1. Bitpack evaluation
    let packed = match compress_compare_pack_7bit(&input_block) {
        Ok(p) => p,
        Err(err) => return Err(err),
    };
    let unpacked = match compress_compare_unpack_7bit(&packed) {
        Ok(u) => u,
        Err(err) => return Err(err),
    };
    if unpacked.get()? != input_block.get()? {
        return Err(CompressCompareError::CcEvalSentenceMismatch);
    }

    // 2. Static Huffman evaluation
    let huff_enc = match compress_compare_huffman_encode(&input_block) {
        Ok(h) => h,
        Err(err) => return Err(err),
    };
    let huff_dec = match compress_compare_huffman_decode(&huff_enc) {
        Ok(h) => h,
        Err(err) => return Err(err),
    };
    if huff_dec.get()? != input_block.get()? {
        return Err(CompressCompareError::CcEvalSentenceMismatch);
    }

    // 3. Tokenize evaluation
    let tok_enc = match compress_compare_tokenize_encode(&input_block) {
        Ok(t) => t,
        Err(err) => return Err(err),
    };
    let tok_dec = match compress_compare_tokenize_decode(&tok_enc) {
        Ok(t) => t,
        Err(err) => return Err(err),
    };
    if tok_dec.get()? != input_block.get()? {
        return Err(CompressCompareError::CcEvalSentenceMismatch);
    }

    Ok(CompressCompareBenchmarkMetrics {
        raw_bytes: input_block.len(),
        bitpack_bytes: packed.length(),
        huffman_bytes: huff_enc.length(),
        tokenized_bytes: tok_enc.length(),
    })
}

// =============================================================================
// SECTION: TIMING / DURATION HARNESS
// -----------------------------------------------------------------------------
// Purpose:
//   Measure per-packet codec latency (encode and decode) for each of the three
//   candidate algorithms, so that the comparison report can weigh compression
//   ratio against CPU cost on the UDP send/receive hot path.
//
// Measurement policy (documented intent):
//   1. `std::hint::black_box` guards both the input reference and the produced
//      value, so the optimiser cannot hoist the call out of the loop or delete
//      it entirely.
//   2. A fixed warm-up burst runs before the timed region (i-cache priming,
//      branch-predictor training, CPU frequency ramp).
//   3. Each measurement is the MEDIAN of `CC_TIMING_BATCH_COUNT` batches.
//      Median (not mean) is used because a single scheduler preemption or
//      interrupt storm inflates a mean without bound, while it moves a median
//      of an odd-sized sample by at most one rank.
//   4. Results are accumulated in PICOSECONDS per operation
//      (total_nanoseconds * 1000 / iterations). These codecs run in the tens to
//      hundreds of nanoseconds, so integer nanoseconds-per-op would quantise
//      away the signal. No floating point is used inside the measurement path;
//      f64 appears only in the presentation layer of `main.rs`.
//   5. `std::time::Instant` is monotonic by contract, so `elapsed()` cannot go
//      backwards. A ZERO elapsed time across a whole batch is nonetheless
//      suspicious (work optimised away, or clock granularity too coarse). This
//      is recorded as `timing_resolution_suspect` rather than raised as an
//      error: policy is that the report DEGRADES, it does not DISAPPEAR.
//
// Portability note:
//   This section is the only part of the module that requires `std` (for
//   `std::time`). The compression algorithms above are `core`-compatible. If a
//   `no_std` target is ever required, gate this section behind a cargo feature.
//   MSRV for this section: Rust 1.66 (stabilisation of `std::hint::black_box`).
// =============================================================================

use std::hint::black_box;
use std::time::{Duration, Instant};

/// Upper bound on iterations per timed batch. Bounds total runtime and keeps
/// the picosecond accumulator far from `u64` overflow.
pub const CC_TIMING_MAX_ITERATIONS_PER_BATCH: u32 = 100_000;

/// Number of independent batches per measurement. MUST be odd so that the
/// median is a single unambiguous sample requiring no averaging.
pub const CC_TIMING_BATCH_COUNT: usize = 7;

/// Untimed warm-up iterations executed before each timed batch.
pub const CC_TIMING_WARMUP_ITERATIONS: u32 = 64;

/// Scale factor used to retain sub-nanosecond resolution with integer math.
pub const CC_PICOSECONDS_PER_NANOSECOND: u64 = 1_000;

/// `CC_MAX_BLOCK_CAPACITY` expressed as `u8` for length sanity checks.
pub const CC_MAX_BLOCK_CAPACITY_U8: u8 = 128;

// Compile-time invariants for the timing harness configuration.
const _: () = assert!(
    CC_TIMING_BATCH_COUNT % 2 == 1,
    "CC_TIMING_BATCH_COUNT must be odd so the median is a single sample"
);
const _: () = assert!(
    CC_TIMING_BATCH_COUNT >= 3,
    "CC_TIMING_BATCH_COUNT must be at least 3 for the median to reject an outlier"
);
const _: () = assert!(
    CC_MAX_BLOCK_CAPACITY_U8 as usize == CC_MAX_BLOCK_CAPACITY,
    "CC_MAX_BLOCK_CAPACITY_U8 has drifted from CC_MAX_BLOCK_CAPACITY"
);

/// Function-pointer shape of every compression entry point in this module.
/// Using a plain `fn` pointer (rather than a generic or a boxed closure) keeps
/// the harness monomorphisation-free and heap-free.
pub type CcEncodeFunctionPointer =
    fn(
        &CompressCompareAsciiBlock128,
    ) -> Result<CompressCompareCompressedBlock128, CompressCompareError>;

/// Function-pointer shape of every decompression entry point in this module.
pub type CcDecodeFunctionPointer = fn(
    &CompressCompareCompressedBlock128,
)
    -> Result<CompressCompareAsciiBlock128, CompressCompareError>;

/// Enforced Custom Type: a validated, non-zero, bounded iteration count.
///
/// Prevents two concrete failure modes:
///   * divide-by-zero when computing picoseconds-per-operation,
///   * an unbounded loop from a corrupted or mis-typed configuration value.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CompressCompareIterationCount {
    iteration_count_value: u32,
}

impl CompressCompareIterationCount {
    /// Constructs a validated iteration count in `1..=CC_TIMING_MAX_ITERATIONS_PER_BATCH`.
    ///
    /// This is caller-input validation (an expected failure mode), therefore it
    /// reports via error code and debug `eprintln!` only -- never `debug_assert!`.
    pub fn new(requested_iteration_count: u32) -> Result<Self, CompressCompareError> {
        if requested_iteration_count == 0 {
            #[cfg(debug_assertions)]
            eprintln!("CC-1601: timing iteration count of zero is not measurable");
            return Err(CompressCompareError::CcTimingIterationsZero);
        }

        if requested_iteration_count > CC_TIMING_MAX_ITERATIONS_PER_BATCH {
            #[cfg(debug_assertions)]
            eprintln!(
                "CC-1602: timing iteration count {} exceeds maximum {}",
                requested_iteration_count, CC_TIMING_MAX_ITERATIONS_PER_BATCH
            );
            return Err(CompressCompareError::CcTimingIterationsTooLarge);
        }

        Ok(Self {
            iteration_count_value: requested_iteration_count,
        })
    }

    /// Re-validates the stored bound. Guards against post-construction
    /// corruption (bit-flip, adversarial memory write) before the value is used
    /// as a loop bound or a divisor.
    pub fn validity_recheck(&self) -> Result<(), CompressCompareError> {
        if self.iteration_count_value == 0
            || self.iteration_count_value > CC_TIMING_MAX_ITERATIONS_PER_BATCH
        {
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(false, "Invariant Violated: iteration count out of bounds");
            #[cfg(debug_assertions)]
            eprintln!(
                "CC-1603: iteration count corrupted, value: {}",
                self.iteration_count_value
            );
            return Err(CompressCompareError::CcTimingIterationCountCorrupt);
        }
        Ok(())
    }

    /// Accessor. Performs a mandatory validity recheck before yielding the value.
    pub fn get(&self) -> Result<u32, CompressCompareError> {
        match self.validity_recheck() {
            Ok(()) => Ok(self.iteration_count_value),
            Err(error_code) => Err(error_code),
        }
    }
}

/// Per-sentence codec latency results, in PICOSECONDS per single operation.
///
/// All fields are plain `Copy` integers: this struct is safe to return by value
/// from the production path and contains no heap data and no payload content.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CompressCompareTimingMetrics {
    pub pack7_encode_picos_per_op: u64,
    pub pack7_decode_picos_per_op: u64,
    pub huffman_encode_picos_per_op: u64,
    pub huffman_decode_picos_per_op: u64,
    pub tokenize_encode_picos_per_op: u64,
    pub tokenize_decode_picos_per_op: u64,
    /// Iterations executed inside each timed batch.
    pub iterations_per_batch: u32,
    /// Number of batches whose median produced the figures above.
    pub batches_executed: u8,
    /// `true` when at least one measurement produced zero elapsed time,
    /// indicating insufficient clock resolution or eliminated work.
    /// The figures are still reported, flagged with a footnote.
    pub timing_resolution_suspect: bool,
}

/// Converts an elapsed `Duration` plus an iteration count into picoseconds per
/// single operation, with no panicking arithmetic anywhere on the path.
fn cc_picoseconds_per_operation(
    elapsed_duration: Duration,
    iteration_count: u32,
) -> Result<u64, CompressCompareError> {
    let elapsed_nanoseconds_u128 = elapsed_duration.as_nanos();

    let elapsed_nanoseconds_u64 = match u64::try_from(elapsed_nanoseconds_u128) {
        Ok(value) => value,
        Err(_conversion_error) => {
            #[cfg(debug_assertions)]
            eprintln!("CC-1604: elapsed nanoseconds exceed u64 range: {_conversion_error}");
            return Err(CompressCompareError::CcTimingDurationOverflow);
        }
    };

    let elapsed_picoseconds_total =
        match elapsed_nanoseconds_u64.checked_mul(CC_PICOSECONDS_PER_NANOSECOND) {
            Some(value) => value,
            None => {
                #[cfg(debug_assertions)]
                eprintln!("CC-1604: picosecond scaling overflowed u64");
                return Err(CompressCompareError::CcTimingDurationOverflow);
            }
        };

    if iteration_count == 0 {
        #[cfg(all(debug_assertions, not(test)))]
        debug_assert!(
            false,
            "Invariant Violated: zero divisor reached timing math"
        );
        #[cfg(debug_assertions)]
        eprintln!("CC-1605: zero iteration divisor in timing math");
        return Err(CompressCompareError::CcTimingDivisionByZero);
    }

    match elapsed_picoseconds_total.checked_div(iteration_count as u64) {
        Some(value) => Ok(value),
        None => Err(CompressCompareError::CcTimingDivisionByZero),
    }
}

/// Times one batch of `iteration_count` encode operations.
/// Returns picoseconds per single encode operation.
fn cc_time_encode_batch_picos(
    encode_function: CcEncodeFunctionPointer,
    input_block: &CompressCompareAsciiBlock128,
    iteration_count: CompressCompareIterationCount,
) -> Result<u64, CompressCompareError> {
    let iteration_total = match iteration_count.get() {
        Ok(value) => value,
        Err(error_code) => return Err(error_code),
    };

    // --- Untimed warm-up (firmly bounded loop) -------------------------------
    let mut warmup_index: u32 = 0;
    while warmup_index < CC_TIMING_WARMUP_ITERATIONS {
        match encode_function(black_box(input_block)) {
            Ok(produced_block) => {
                let observed_length = black_box(produced_block).length();
                if observed_length > CC_MAX_BLOCK_CAPACITY_U8 {
                    return Err(CompressCompareError::CcTimingUnexpectedBlockLength);
                }
            }
            Err(error_code) => return Err(error_code),
        }
        warmup_index = match warmup_index.checked_add(1) {
            Some(next_index) => next_index,
            None => return Err(CompressCompareError::CcTimingLoopCounterOverflow),
        };
    }

    // --- Timed region (firmly bounded loop) ----------------------------------
    let batch_started_instant = Instant::now();
    let mut run_index: u32 = 0;
    while run_index < iteration_total {
        match encode_function(black_box(input_block)) {
            Ok(produced_block) => {
                let observed_length = black_box(produced_block).length();
                if observed_length > CC_MAX_BLOCK_CAPACITY_U8 {
                    return Err(CompressCompareError::CcTimingUnexpectedBlockLength);
                }
            }
            Err(error_code) => return Err(error_code),
        }
        run_index = match run_index.checked_add(1) {
            Some(next_index) => next_index,
            None => return Err(CompressCompareError::CcTimingLoopCounterOverflow),
        };
    }
    let batch_elapsed_duration = batch_started_instant.elapsed();

    cc_picoseconds_per_operation(batch_elapsed_duration, iteration_total)
}

/// Times one batch of `iteration_count` decode operations.
/// Returns picoseconds per single decode operation.
fn cc_time_decode_batch_picos(
    decode_function: CcDecodeFunctionPointer,
    compressed_block: &CompressCompareCompressedBlock128,
    iteration_count: CompressCompareIterationCount,
) -> Result<u64, CompressCompareError> {
    let iteration_total = match iteration_count.get() {
        Ok(value) => value,
        Err(error_code) => return Err(error_code),
    };

    let mut warmup_index: u32 = 0;
    while warmup_index < CC_TIMING_WARMUP_ITERATIONS {
        match decode_function(black_box(compressed_block)) {
            Ok(restored_block) => {
                let observed_length = black_box(restored_block).len();
                if observed_length > CC_MAX_BLOCK_CAPACITY_U8 {
                    return Err(CompressCompareError::CcTimingUnexpectedBlockLength);
                }
            }
            Err(error_code) => return Err(error_code),
        }
        warmup_index = match warmup_index.checked_add(1) {
            Some(next_index) => next_index,
            None => return Err(CompressCompareError::CcTimingLoopCounterOverflow),
        };
    }

    let batch_started_instant = Instant::now();
    let mut run_index: u32 = 0;
    while run_index < iteration_total {
        match decode_function(black_box(compressed_block)) {
            Ok(restored_block) => {
                let observed_length = black_box(restored_block).len();
                if observed_length > CC_MAX_BLOCK_CAPACITY_U8 {
                    return Err(CompressCompareError::CcTimingUnexpectedBlockLength);
                }
            }
            Err(error_code) => return Err(error_code),
        }
        run_index = match run_index.checked_add(1) {
            Some(next_index) => next_index,
            None => return Err(CompressCompareError::CcTimingLoopCounterOverflow),
        };
    }
    let batch_elapsed_duration = batch_started_instant.elapsed();

    cc_picoseconds_per_operation(batch_elapsed_duration, iteration_total)
}

/// In-place ascending insertion sort over the fixed batch-sample array.
///
/// Insertion sort is chosen deliberately: it is non-recursive (Rule 1), has a
/// firmly bounded trip count for a fixed-size array (Rule 2), needs no scratch
/// allocation (Rule 3), and is optimal for `CC_TIMING_BATCH_COUNT == 7`.
fn cc_sort_timing_samples_ascending(
    timing_samples: &mut [u64; CC_TIMING_BATCH_COUNT],
) -> Result<(), CompressCompareError> {
    let mut outer_index: usize = 1;
    while outer_index < CC_TIMING_BATCH_COUNT {
        let mut inner_index: usize = outer_index;
        while inner_index > 0 {
            let previous_index = match inner_index.checked_sub(1) {
                Some(index) => index,
                None => return Err(CompressCompareError::CcTimingIndexOutOfRange),
            };

            let current_value = match timing_samples.get(inner_index) {
                Some(&value) => value,
                None => return Err(CompressCompareError::CcTimingIndexOutOfRange),
            };
            let previous_value = match timing_samples.get(previous_index) {
                Some(&value) => value,
                None => return Err(CompressCompareError::CcTimingIndexOutOfRange),
            };

            if previous_value <= current_value {
                break;
            }

            timing_samples.swap(previous_index, inner_index);
            inner_index = previous_index;
        }

        outer_index = match outer_index.checked_add(1) {
            Some(next_index) => next_index,
            None => return Err(CompressCompareError::CcTimingLoopCounterOverflow),
        };
    }
    Ok(())
}

/// Returns the median of a fixed batch-sample array (array is sorted in place).
fn cc_median_of_timing_samples(
    timing_samples: &mut [u64; CC_TIMING_BATCH_COUNT],
) -> Result<u64, CompressCompareError> {
    match cc_sort_timing_samples_ascending(timing_samples) {
        Ok(()) => (),
        Err(error_code) => return Err(error_code),
    }

    let median_index = CC_TIMING_BATCH_COUNT / 2; // total: literal nonzero divisor
    match timing_samples.get(median_index) {
        Some(&median_value) => Ok(median_value),
        None => {
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(
                false,
                "Invariant Violated: median index outside sample array"
            );
            #[cfg(debug_assertions)]
            eprintln!(
                "CC-1606: median index {} outside sample array",
                median_index
            );
            Err(CompressCompareError::CcTimingIndexOutOfRange)
        }
    }
}

/// Runs `CC_TIMING_BATCH_COUNT` encode batches and returns the median result.
fn cc_median_encode_picos(
    encode_function: CcEncodeFunctionPointer,
    input_block: &CompressCompareAsciiBlock128,
    iterations_per_batch: CompressCompareIterationCount,
) -> Result<u64, CompressCompareError> {
    let mut batch_samples = [0u64; CC_TIMING_BATCH_COUNT];
    let mut batch_index: usize = 0;

    while batch_index < CC_TIMING_BATCH_COUNT {
        let batch_sample =
            match cc_time_encode_batch_picos(encode_function, input_block, iterations_per_batch) {
                Ok(sample) => sample,
                Err(error_code) => return Err(error_code),
            };

        match batch_samples.get_mut(batch_index) {
            Some(sample_slot) => *sample_slot = batch_sample,
            None => return Err(CompressCompareError::CcTimingIndexOutOfRange),
        }

        batch_index = match batch_index.checked_add(1) {
            Some(next_index) => next_index,
            None => return Err(CompressCompareError::CcTimingLoopCounterOverflow),
        };
    }

    cc_median_of_timing_samples(&mut batch_samples)
}

/// Runs `CC_TIMING_BATCH_COUNT` decode batches and returns the median result.
fn cc_median_decode_picos(
    decode_function: CcDecodeFunctionPointer,
    compressed_block: &CompressCompareCompressedBlock128,
    iterations_per_batch: CompressCompareIterationCount,
) -> Result<u64, CompressCompareError> {
    let mut batch_samples = [0u64; CC_TIMING_BATCH_COUNT];
    let mut batch_index: usize = 0;

    while batch_index < CC_TIMING_BATCH_COUNT {
        let batch_sample = match cc_time_decode_batch_picos(
            decode_function,
            compressed_block,
            iterations_per_batch,
        ) {
            Ok(sample) => sample,
            Err(error_code) => return Err(error_code),
        };

        match batch_samples.get_mut(batch_index) {
            Some(sample_slot) => *sample_slot = batch_sample,
            None => return Err(CompressCompareError::CcTimingIndexOutOfRange),
        }

        batch_index = match batch_index.checked_add(1) {
            Some(next_index) => next_index,
            None => return Err(CompressCompareError::CcTimingLoopCounterOverflow),
        };
    }

    cc_median_of_timing_samples(&mut batch_samples)
}

/// Measures encode and decode latency of all three candidate algorithms for a
/// single ASCII sentence.
///
/// Contract:
///   * `raw_sentence` must be <= `CC_MAX_BLOCK_CAPACITY` bytes of 7-bit ASCII.
///   * Returns `Err` if the sentence is empty, non-ASCII, oversized, or if any
///     codec fails (for example, a Huffman bitstream that expands past the
///     128-byte MTU budget). The caller applies Tier-2 fallback in that case.
///   * Performs no heap allocation and never panics.
pub fn compress_compare_time_sentence(
    raw_sentence: &[u8],
    iterations_per_batch: CompressCompareIterationCount,
) -> Result<CompressCompareTimingMetrics, CompressCompareError> {
    let input_block = match CompressCompareAsciiBlock128::new(raw_sentence) {
        Ok(block) => block,
        Err(error_code) => return Err(error_code),
    };

    if input_block.is_empty() {
        #[cfg(debug_assertions)]
        eprintln!("CC-1402: cannot time an empty sentence block");
        return Err(CompressCompareError::CcEvalSentenceEmpty);
    }

    // Pre-encode once per algorithm so the decode timings have a stable input.
    let packed_block = match compress_compare_pack_7bit(&input_block) {
        Ok(block) => block,
        Err(error_code) => return Err(error_code),
    };
    let huffman_block = match compress_compare_huffman_encode(&input_block) {
        Ok(block) => block,
        Err(error_code) => return Err(error_code),
    };
    let tokenized_block = match compress_compare_tokenize_encode(&input_block) {
        Ok(block) => block,
        Err(error_code) => return Err(error_code),
    };

    let pack7_encode_picos_per_op = match cc_median_encode_picos(
        compress_compare_pack_7bit,
        &input_block,
        iterations_per_batch,
    ) {
        Ok(value) => value,
        Err(error_code) => return Err(error_code),
    };
    let pack7_decode_picos_per_op = match cc_median_decode_picos(
        compress_compare_unpack_7bit,
        &packed_block,
        iterations_per_batch,
    ) {
        Ok(value) => value,
        Err(error_code) => return Err(error_code),
    };
    let huffman_encode_picos_per_op = match cc_median_encode_picos(
        compress_compare_huffman_encode,
        &input_block,
        iterations_per_batch,
    ) {
        Ok(value) => value,
        Err(error_code) => return Err(error_code),
    };
    let huffman_decode_picos_per_op = match cc_median_decode_picos(
        compress_compare_huffman_decode,
        &huffman_block,
        iterations_per_batch,
    ) {
        Ok(value) => value,
        Err(error_code) => return Err(error_code),
    };
    let tokenize_encode_picos_per_op = match cc_median_encode_picos(
        compress_compare_tokenize_encode,
        &input_block,
        iterations_per_batch,
    ) {
        Ok(value) => value,
        Err(error_code) => return Err(error_code),
    };
    let tokenize_decode_picos_per_op = match cc_median_decode_picos(
        compress_compare_tokenize_decode,
        &tokenized_block,
        iterations_per_batch,
    ) {
        Ok(value) => value,
        Err(error_code) => return Err(error_code),
    };

    let iterations_value = match iterations_per_batch.get() {
        Ok(value) => value,
        Err(error_code) => return Err(error_code),
    };

    let batches_executed_u8 = match u8::try_from(CC_TIMING_BATCH_COUNT) {
        Ok(value) => value,
        Err(_conversion_error) => {
            #[cfg(debug_assertions)]
            eprintln!("CC-1606: batch count does not fit u8: {_conversion_error}");
            return Err(CompressCompareError::CcTimingIndexOutOfRange);
        }
    };

    // Resolution policy: report the numbers, flag the doubt (see section header).
    let timing_resolution_suspect = pack7_encode_picos_per_op == 0
        || pack7_decode_picos_per_op == 0
        || huffman_encode_picos_per_op == 0
        || huffman_decode_picos_per_op == 0
        || tokenize_encode_picos_per_op == 0
        || tokenize_decode_picos_per_op == 0;

    Ok(CompressCompareTimingMetrics {
        pack7_encode_picos_per_op,
        pack7_decode_picos_per_op,
        huffman_encode_picos_per_op,
        huffman_decode_picos_per_op,
        tokenize_encode_picos_per_op,
        tokenize_decode_picos_per_op,
        iterations_per_batch: iterations_value,
        batches_executed: batches_executed_u8,
        timing_resolution_suspect,
    })
}

// -----------------------------------------------------------------------------
// CARGO TESTS (Isolated in Test Mode)
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_type_integrity_and_empty() {
        let empty_slice: &[u8] = b"";
        let empty_block = CompressCompareAsciiBlock128::new(empty_slice).unwrap();
        assert!(empty_block.is_empty());
        assert_eq!(empty_block.len(), 0);

        let non_ascii_data = [b'h', b'i', 0x80];
        let bad_block = CompressCompareAsciiBlock128::new(&non_ascii_data);
        assert_eq!(bad_block, Err(CompressCompareError::CcBlockNewNonAscii));

        let oversized = [b'a'; 129];
        let large_block = CompressCompareAsciiBlock128::new(&oversized);
        assert_eq!(
            large_block,
            Err(CompressCompareError::CcBlockNewInputTooLong)
        );
    }

    #[test]
    fn test_error_retryability_mapping() {
        assert!(CompressCompareError::_CcDriverTransientBufferBusy.is_retryable());
        assert!(!CompressCompareError::CcBlockNewNonAscii.is_retryable());
        assert!(!CompressCompareError::CcPack7BitOverflow.is_retryable());
    }

    #[test]
    fn test_7bit_pack_roundtrip_equivalence() {
        let text = b"The quick brown fox jumps over the lazy dog 1234567890.";
        let block = CompressCompareAsciiBlock128::new(text).unwrap();
        let compressed = compress_compare_pack_7bit(&block).unwrap();
        let restored = compress_compare_unpack_7bit(&compressed).unwrap();
        assert_eq!(block.get().unwrap(), restored.get().unwrap());
        assert_eq!(compressed.length(), 49); // 55 * 7 = 385 bits -> 49 bytes
    }

    #[test]
    fn test_huffman_roundtrip_equivalence() {
        let text = b"To be, or not to be, that is the question: Whether 'tis nobler.";
        let block = CompressCompareAsciiBlock128::new(text).unwrap();
        let compressed = compress_compare_huffman_encode(&block).unwrap();
        let restored = compress_compare_huffman_decode(&compressed).unwrap();
        assert_eq!(block.get().unwrap(), restored.get().unwrap());
        assert!(compressed.length() < block.len());
    }

    #[test]
    fn test_tokenization_roundtrip_equivalence() {
        let text = b"that with the and this is standard text within that";
        let block = CompressCompareAsciiBlock128::new(text).unwrap();
        let compressed = compress_compare_tokenize_encode(&block).unwrap();
        let restored = compress_compare_tokenize_decode(&compressed).unwrap();
        assert_eq!(block.get().unwrap(), restored.get().unwrap());
        assert!(compressed.length() < block.len());
    }

    #[test]
    fn test_sentence_evaluation_harness() {
        let sentence = b"Humpty Dumpty sat on a wall, Humpty Dumpty had a great fall.";
        let metrics = compress_compare_evaluate_sentence(sentence).unwrap();
        assert_eq!(metrics.raw_bytes, 60);
        assert!(metrics.bitpack_bytes < metrics.raw_bytes);
        assert!(metrics.huffman_bytes < metrics.raw_bytes);
        assert!(metrics.tokenized_bytes < metrics.raw_bytes);
    }

    #[test]
    fn test_compressed_block_payload_slice_validation() {
        let empty_block = CompressCompareCompressedBlock128::empty();
        let empty_slice = empty_block.payload_slice().unwrap();
        assert_eq!(empty_slice.len(), 0);

        let text = b"Validating payload_slice accessor";
        let block = CompressCompareAsciiBlock128::new(text).unwrap();
        let compressed = compress_compare_pack_7bit(&block).unwrap();
        let slice = compressed.payload_slice().unwrap();
        assert_eq!(slice.len(), compressed.length() as usize);
    }

    #[test]
    fn test_iteration_count_boundaries() {
        assert_eq!(
            CompressCompareIterationCount::new(0),
            Err(CompressCompareError::CcTimingIterationsZero)
        );
        assert_eq!(
            CompressCompareIterationCount::new(CC_TIMING_MAX_ITERATIONS_PER_BATCH + 1),
            Err(CompressCompareError::CcTimingIterationsTooLarge)
        );
        let valid_count = CompressCompareIterationCount::new(16).unwrap();
        assert_eq!(valid_count.get().unwrap(), 16);
    }

    #[test]
    fn test_picoseconds_per_operation_math() {
        // 1 microsecond over 1000 iterations == 1 ns == 1000 ps per operation.
        let elapsed = Duration::from_micros(1);
        assert_eq!(cc_picoseconds_per_operation(elapsed, 1000).unwrap(), 1_000);

        assert_eq!(
            cc_picoseconds_per_operation(elapsed, 0),
            Err(CompressCompareError::CcTimingDivisionByZero)
        );
    }

    #[test]
    fn test_median_of_timing_samples_rejects_outliers() {
        // One catastrophic outlier (preemption) must not move the median.
        let mut samples: [u64; CC_TIMING_BATCH_COUNT] = [420, 410, 430, 9_999_999, 415, 425, 405];
        assert_eq!(cc_median_of_timing_samples(&mut samples).unwrap(), 420);
        // Post-condition: the array is sorted ascending.
        let mut index = 1;
        while index < CC_TIMING_BATCH_COUNT {
            assert!(samples[index - 1] <= samples[index]);
            index += 1;
        }
    }

    #[test]
    fn test_time_sentence_produces_plausible_metrics() {
        // Small iteration count keeps the test suite fast.
        let iterations = CompressCompareIterationCount::new(64).unwrap();
        let sentence = b"All the world's a stage, and all the men and women merely players.";
        let timing = compress_compare_time_sentence(sentence, iterations).unwrap();

        assert_eq!(timing.iterations_per_batch, 64);
        assert_eq!(timing.batches_executed as usize, CC_TIMING_BATCH_COUNT);
        // NOTE: deliberately no assertion on absolute latency values. Wall-clock
        // thresholds make tests flaky on shared CI runners.
    }

    #[test]
    fn test_time_sentence_rejects_empty_input() {
        let iterations = CompressCompareIterationCount::new(8).unwrap();
        assert_eq!(
            compress_compare_time_sentence(b"", iterations),
            Err(CompressCompareError::CcEvalSentenceEmpty)
        );
    }
}
