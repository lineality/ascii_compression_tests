//! ============================================================================
//! File Path: /src/main.rs
//! Project: Safety-Critical UDP ASCII Text Compression Benchmark Driver
//! Development Phase: Production-Release (Supervisory & Reporting Layer)
//! Architecture: Single-Flat Module `compress_compare.rs`
//!
//! Report structure:
//!   TABLE 1 - Compression ratio (bytes saved per algorithm).
//!   TABLE 2 - Codec latency, nanoseconds per single 128-byte-budget operation,
//!             encode and decode measured separately.
//!   SUMMARY - Dataset-wide averages, encode throughput, and wall-clock totals.
//!
//! Phase separation: ALL measurement completes before ANY table is printed, so
//! that stdout flushing never contaminates a timed region, and so a Tier-3
//! restart cannot emit a partially written table.
//! ============================================================================

#![forbid(unsafe_code)]

mod compression_socks;

use compression_socks::{
    CC_TIMING_BATCH_COUNT, CompressCompareBenchmarkMetrics, CompressCompareError,
    CompressCompareIterationCount, CompressCompareTimingMetrics,
    compress_compare_evaluate_sentence, compress_compare_time_sentence,
};

use std::time::Instant;

/// Bounded retry ceiling for Tier-1 micro-retries.
const CC_MAX_LOCAL_RETRIES: u8 = 3;

/// Bounded ceiling for Tier-3 supervisory re-initialisations.
const CC_MAX_SUPERVISORY_REBOOTS: u8 = 2;

/// Iterations executed inside each timed batch. Total operations per sentence
/// equal: 6 measurements * CC_TIMING_BATCH_COUNT batches * this value.
const CC_TIMING_ITERATIONS_PER_BATCH: u32 = 2_000;

/// Evaluation dataset: Shakespeare lines, nursery rhymes, and UDP telemetry strings (all <= 128 bytes).
const CC_DATASET_SENTENCES: &[&str] = &[
    "To be, or not to be, that is the question: Whether 'tis nobler in the mind to suffer slings and arrows.",
    "All the world's a stage, and all the men and women merely players: they have their exits and entrances.",
    "Humpty Dumpty sat on a wall, Humpty Dumpty had a great fall. All the king's horses and men could not fix it.",
    "Mary had a little lamb, its fleece was white as snow; and everywhere that Mary went, the lamb was sure to go.",
    "status=ok sensor=temp_probe_4 zone=north_rack value=42.8 alert=none retry_count=0 timestamp=1726142400",
    "Peace, cousin, say no more. And now I will unclasp a secret book ...On the unsteadfast footing of a spear.",
    "And to your quick conceiving discontents I'll read you matter deep and dangerous,",
    "FALSTAFF Do so, for it is worth the listening to. These nine in buckram that I told thee of",
];

/// Compile-time fixed dataset length, so results live in a stack array (Rule 3).
const CC_DATASET_LENGTH: usize = 8;
const _: () = assert!(
    CC_DATASET_SENTENCES.len() == CC_DATASET_LENGTH,
    "CC_DATASET_LENGTH has drifted from CC_DATASET_SENTENCES"
);

const CC_REPORT_RULE_LINE: &str = "====================================================================================================";
const CC_REPORT_THIN_LINE: &str = "----------------------------------------------------------------------------------------------------";

/// One fully measured dataset row: size metrics plus latency metrics.
#[derive(Copy, Clone, Debug)]
struct CcDriverResultRow {
    size_metrics: CompressCompareBenchmarkMetrics,
    timing_metrics: CompressCompareTimingMetrics,
}

/// Converts picoseconds-per-operation into nanoseconds for display only.
/// Presentation-layer floating point; never used in the measurement path.
fn cc_picos_to_nanos_f64(picoseconds_per_operation: u64) -> f64 {
    (picoseconds_per_operation as f64) / 1000.0
}

/// Encode-path throughput in megabytes per second, derived from raw payload
/// bytes and picoseconds per operation. Returns 0.0 when the timing is zero
/// (resolution-suspect), so the report degrades rather than dividing by zero.
fn cc_megabytes_per_second(payload_bytes: u8, picoseconds_per_operation: u64) -> f64 {
    if picoseconds_per_operation == 0 {
        return 0.0;
    }
    // bytes / (picos * 1e-12 s) / 1e6 == bytes * 1e6 / picos
    (payload_bytes as f64) * 1_000_000.0 / (picoseconds_per_operation as f64)
}

/// Safe integer mean over a bounded sample count; returns 0 for an empty set.
fn cc_mean_picos(accumulated_picos: u64, sample_count: u32) -> u64 {
    if sample_count == 0 {
        return 0;
    }
    match accumulated_picos.checked_div(sample_count as u64) {
        Some(mean_value) => mean_value,
        None => 0,
    }
}

/// Top-level execution driver adhering to the Three-Level Recovery Hierarchy.
fn main() -> Result<(), CompressCompareError> {
    let program_started_instant = Instant::now();

    // Validated once, outside every loop: a corrupted configuration must fail
    // before any measurement begins, not halfway through a table.
    let iterations_per_batch =
        match CompressCompareIterationCount::new(CC_TIMING_ITERATIONS_PER_BATCH) {
            Ok(count) => count,
            Err(error_code) => {
                eprintln!(
                    "FATAL: invalid timing configuration, code {}",
                    error_code as u16
                );
                return Err(error_code);
            }
        };

    let mut supervisory_reboot_count: u8 = 0;

    // =========================================================================
    // RECOVERY TIER 3: Macro Re-initialization Loop
    // =========================================================================
    let measured_rows: [Option<CcDriverResultRow>; CC_DATASET_LENGTH] = 'macro_supervisory_loop: loop {
        let mut working_rows: [Option<CcDriverResultRow>; CC_DATASET_LENGTH] =
            [None; CC_DATASET_LENGTH];
        let mut dataset_index: usize = 0;
        let mut macro_fatal_fault = false;

        while dataset_index < CC_DATASET_LENGTH {
            let sentence_text = match CC_DATASET_SENTENCES.get(dataset_index) {
                Some(&text) => text,
                None => {
                    macro_fatal_fault = true;
                    break;
                }
            };

            // =================================================================
            // RECOVERY TIER 1: Local Micro-Retry Loop (queries is_retryable())
            // NOTE: the codec path is deterministic and allocation-free, so no
            // error it produces is currently retryable. The loop is retained as
            // the integration point for future transient sources (clock
            // anomalies, shared-buffer contention in the live UDP driver).
            // =================================================================
            let mut local_retry_count: u8 = 0;
            let completed_row: Option<CcDriverResultRow> = loop {
                let size_metrics = match compress_compare_evaluate_sentence(
                    sentence_text.as_bytes(),
                ) {
                    Ok(metrics) => metrics,
                    Err(error_code) => {
                        if error_code.is_retryable() && local_retry_count < CC_MAX_LOCAL_RETRIES {
                            local_retry_count = match local_retry_count.checked_add(1) {
                                Some(next_count) => next_count,
                                None => break None,
                            };
                            #[cfg(debug_assertions)]
                            eprintln!(
                                "TIER-1 RETRY: sentence #{} transient fault code {}, retrying ({}/{})",
                                dataset_index + 1,
                                error_code as u16,
                                local_retry_count,
                                CC_MAX_LOCAL_RETRIES
                            );
                            continue;
                        }
                        // =========================================================
                        // RECOVERY TIER 2: Step Fallback / Safe Degradation
                        // =========================================================
                        #[cfg(debug_assertions)]
                        eprintln!(
                            "TIER-2 FALLBACK: sentence #{} permanent fault code {} during sizing, skipping row.",
                            dataset_index + 1,
                            error_code as u16
                        );
                        break None;
                    }
                };

                let timing_metrics = match compress_compare_time_sentence(
                    sentence_text.as_bytes(),
                    iterations_per_batch,
                ) {
                    Ok(timing) => timing,
                    Err(error_code) => {
                        if error_code.is_retryable() && local_retry_count < CC_MAX_LOCAL_RETRIES {
                            local_retry_count = match local_retry_count.checked_add(1) {
                                Some(next_count) => next_count,
                                None => break None,
                            };
                            #[cfg(debug_assertions)]
                            eprintln!(
                                "TIER-1 RETRY: sentence #{} transient timing fault code {}, retrying ({}/{})",
                                dataset_index + 1,
                                error_code as u16,
                                local_retry_count,
                                CC_MAX_LOCAL_RETRIES
                            );
                            continue;
                        }
                        #[cfg(debug_assertions)]
                        eprintln!(
                            "TIER-2 FALLBACK: sentence #{} permanent fault code {} during timing, skipping row.",
                            dataset_index + 1,
                            error_code as u16
                        );
                        break None;
                    }
                };

                break Some(CcDriverResultRow {
                    size_metrics,
                    timing_metrics,
                });
            };

            match working_rows.get_mut(dataset_index) {
                Some(row_slot) => *row_slot = completed_row,
                None => {
                    macro_fatal_fault = true;
                    break;
                }
            }

            dataset_index = match dataset_index.checked_add(1) {
                Some(next_index) => next_index,
                None => {
                    macro_fatal_fault = true;
                    break;
                }
            };
        }

        if !macro_fatal_fault {
            break 'macro_supervisory_loop working_rows;
        }

        supervisory_reboot_count = match supervisory_reboot_count.checked_add(1) {
            Some(reboot_count) if reboot_count <= CC_MAX_SUPERVISORY_REBOOTS => {
                #[cfg(debug_assertions)]
                eprintln!(
                    "TIER-3 REBOOT: re-initializing supervisor loop (attempt {})",
                    reboot_count
                );
                reboot_count
            }
            _ => {
                eprintln!("TIER-3 HALT: unrecoverable supervisory state failure.");
                return Err(CompressCompareError::CcDriverSupervisoryUnrecoverable);
            }
        };
    };

    let measurement_elapsed_duration = program_started_instant.elapsed();

    // =========================================================================
    // REPORTING PHASE (no measurement occurs beyond this point)
    // =========================================================================
    println!("{CC_REPORT_RULE_LINE}");
    println!(" ASCII 128-BYTE UDP COMPRESSION COMPARISON BENCHMARK (SAFETY-CRITICAL DRIVER)");
    #[cfg(debug_assertions)]
    println!(
        " BUILD PROFILE: DEBUG -- latency figures are NOT representative. Use `cargo run --release`."
    );
    #[cfg(not(debug_assertions))]
    println!(" BUILD PROFILE: RELEASE");
    println!("{CC_REPORT_RULE_LINE}");

    // ---------------------------- TABLE 1 ------------------------------------
    println!(" TABLE 1: COMPRESSED SIZE (bytes, and percent saved versus raw ASCII)");
    println!("{CC_REPORT_THIN_LINE}");
    println!(
        "{:<4} | {:<7} | {:<12} | {:<12} | {:<12} | {:<15}",
        "#", "Raw(B)", "7-Bit Pack", "Huffman", "8th-Bit Tok", "Best Candidate"
    );
    println!("{CC_REPORT_THIN_LINE}");

    let mut report_index: usize = 0;
    while report_index < CC_DATASET_LENGTH {
        match measured_rows.get(report_index) {
            Some(Some(result_row)) => {
                let size_metrics = result_row.size_metrics;
                let raw_bytes_f64 = size_metrics.raw_bytes as f64;
                let pack_saved_percent =
                    100.0 * (1.0 - (size_metrics.bitpack_bytes as f64 / raw_bytes_f64));
                let huffman_saved_percent =
                    100.0 * (1.0 - (size_metrics.huffman_bytes as f64 / raw_bytes_f64));
                let token_saved_percent =
                    100.0 * (1.0 - (size_metrics.tokenized_bytes as f64 / raw_bytes_f64));

                let best_algorithm_name = if size_metrics.huffman_bytes
                    <= size_metrics.tokenized_bytes
                    && size_metrics.huffman_bytes <= size_metrics.bitpack_bytes
                {
                    "Huffman"
                } else if size_metrics.tokenized_bytes <= size_metrics.bitpack_bytes {
                    "8th-Bit Token"
                } else {
                    "7-Bit Pack"
                };

                println!(
                    "{:<4} | {:<7} | {:>3}B ({:>4.1}%) | {:>3}B ({:>4.1}%) | {:>3}B ({:>4.1}%) | {:<15}",
                    report_index + 1,
                    size_metrics.raw_bytes,
                    size_metrics.bitpack_bytes,
                    pack_saved_percent,
                    size_metrics.huffman_bytes,
                    huffman_saved_percent,
                    size_metrics.tokenized_bytes,
                    token_saved_percent,
                    best_algorithm_name
                );
            }
            Some(None) => {
                println!(
                    "{:<4} | {:<7} | {:<12} | {:<12} | {:<12} | {:<15}",
                    report_index + 1,
                    "--",
                    "SKIPPED",
                    "SKIPPED",
                    "SKIPPED",
                    "tier-2 fallback"
                );
            }
            None => break,
        }

        report_index = match report_index.checked_add(1) {
            Some(next_index) => next_index,
            None => break,
        };
    }

    // ---------------------------- TABLE 2 ------------------------------------
    println!("{CC_REPORT_RULE_LINE}");
    println!(
        " TABLE 2: CODEC LATENCY, nanoseconds per operation (median of {} batches x {} iterations)",
        CC_TIMING_BATCH_COUNT, CC_TIMING_ITERATIONS_PER_BATCH
    );
    println!("{CC_REPORT_THIN_LINE}");
    println!(
        "{:<4} | {:>9} | {:>9} | {:>9} | {:>9} | {:>9} | {:>9} | {:<13}",
        "#", "Pk7 Enc", "Pk7 Dec", "Huf Enc", "Huf Dec", "Tok Enc", "Tok Dec", "Fastest Enc"
    );
    println!("{CC_REPORT_THIN_LINE}");

    let mut pack7_encode_picos_sum: u64 = 0;
    let mut pack7_decode_picos_sum: u64 = 0;
    let mut huffman_encode_picos_sum: u64 = 0;
    let mut huffman_decode_picos_sum: u64 = 0;
    let mut tokenize_encode_picos_sum: u64 = 0;
    let mut tokenize_decode_picos_sum: u64 = 0;
    let mut raw_bytes_sum: u64 = 0;
    let mut timed_row_count: u32 = 0;
    let mut any_resolution_suspect = false;

    report_index = 0;
    while report_index < CC_DATASET_LENGTH {
        match measured_rows.get(report_index) {
            Some(Some(result_row)) => {
                let timing_metrics = result_row.timing_metrics;

                let fastest_encoder_name = if timing_metrics.tokenize_encode_picos_per_op
                    <= timing_metrics.pack7_encode_picos_per_op
                    && timing_metrics.tokenize_encode_picos_per_op
                        <= timing_metrics.huffman_encode_picos_per_op
                {
                    "8th-Bit Token"
                } else if timing_metrics.pack7_encode_picos_per_op
                    <= timing_metrics.huffman_encode_picos_per_op
                {
                    "7-Bit Pack"
                } else {
                    "Huffman"
                };

                println!(
                    "{:<4} | {:>9.2} | {:>9.2} | {:>9.2} | {:>9.2} | {:>9.2} | {:>9.2} | {:<13}{}",
                    report_index + 1,
                    cc_picos_to_nanos_f64(timing_metrics.pack7_encode_picos_per_op),
                    cc_picos_to_nanos_f64(timing_metrics.pack7_decode_picos_per_op),
                    cc_picos_to_nanos_f64(timing_metrics.huffman_encode_picos_per_op),
                    cc_picos_to_nanos_f64(timing_metrics.huffman_decode_picos_per_op),
                    cc_picos_to_nanos_f64(timing_metrics.tokenize_encode_picos_per_op),
                    cc_picos_to_nanos_f64(timing_metrics.tokenize_decode_picos_per_op),
                    fastest_encoder_name,
                    if timing_metrics.timing_resolution_suspect {
                        " (*)"
                    } else {
                        ""
                    }
                );

                if timing_metrics.timing_resolution_suspect {
                    any_resolution_suspect = true;
                }

                // Accumulate with checked arithmetic; on overflow, stop
                // accumulating rather than reporting a wrapped average.
                pack7_encode_picos_sum = pack7_encode_picos_sum
                    .checked_add(timing_metrics.pack7_encode_picos_per_op)
                    .unwrap_or(pack7_encode_picos_sum);
                pack7_decode_picos_sum = pack7_decode_picos_sum
                    .checked_add(timing_metrics.pack7_decode_picos_per_op)
                    .unwrap_or(pack7_decode_picos_sum);
                huffman_encode_picos_sum = huffman_encode_picos_sum
                    .checked_add(timing_metrics.huffman_encode_picos_per_op)
                    .unwrap_or(huffman_encode_picos_sum);
                huffman_decode_picos_sum = huffman_decode_picos_sum
                    .checked_add(timing_metrics.huffman_decode_picos_per_op)
                    .unwrap_or(huffman_decode_picos_sum);
                tokenize_encode_picos_sum = tokenize_encode_picos_sum
                    .checked_add(timing_metrics.tokenize_encode_picos_per_op)
                    .unwrap_or(tokenize_encode_picos_sum);
                tokenize_decode_picos_sum = tokenize_decode_picos_sum
                    .checked_add(timing_metrics.tokenize_decode_picos_per_op)
                    .unwrap_or(tokenize_decode_picos_sum);
                raw_bytes_sum = raw_bytes_sum
                    .checked_add(result_row.size_metrics.raw_bytes as u64)
                    .unwrap_or(raw_bytes_sum);
                timed_row_count = timed_row_count.checked_add(1).unwrap_or(timed_row_count);
            }
            Some(None) => {
                println!(
                    "{:<4} | {:>9} | {:>9} | {:>9} | {:>9} | {:>9} | {:>9} | {:<13}",
                    report_index + 1,
                    "--",
                    "--",
                    "--",
                    "--",
                    "--",
                    "--",
                    "skipped"
                );
            }
            None => break,
        }

        report_index = match report_index.checked_add(1) {
            Some(next_index) => next_index,
            None => break,
        };
    }

    // ---------------------------- SUMMARY ------------------------------------
    println!("{CC_REPORT_RULE_LINE}");
    println!(
        " SUMMARY: dataset means over {} timed row(s)",
        timed_row_count
    );
    println!("{CC_REPORT_THIN_LINE}");

    let mean_raw_bytes_u8 = match u8::try_from(cc_mean_picos(raw_bytes_sum, timed_row_count)) {
        Ok(value) => value,
        Err(_conversion_error) => 0,
    };

    let pack7_encode_mean_picos = cc_mean_picos(pack7_encode_picos_sum, timed_row_count);
    let huffman_encode_mean_picos = cc_mean_picos(huffman_encode_picos_sum, timed_row_count);
    let tokenize_encode_mean_picos = cc_mean_picos(tokenize_encode_picos_sum, timed_row_count);

    println!(
        "{:<15} | {:>12} | {:>12} | {:>14}",
        "Algorithm", "Enc ns/op", "Dec ns/op", "Enc MB/s"
    );
    println!(
        "{:<15} | {:>12.2} | {:>12.2} | {:>14.1}",
        "7-Bit Pack",
        cc_picos_to_nanos_f64(pack7_encode_mean_picos),
        cc_picos_to_nanos_f64(cc_mean_picos(pack7_decode_picos_sum, timed_row_count)),
        cc_megabytes_per_second(mean_raw_bytes_u8, pack7_encode_mean_picos)
    );
    println!(
        "{:<15} | {:>12.2} | {:>12.2} | {:>14.1}",
        "Huffman",
        cc_picos_to_nanos_f64(huffman_encode_mean_picos),
        cc_picos_to_nanos_f64(cc_mean_picos(huffman_decode_picos_sum, timed_row_count)),
        cc_megabytes_per_second(mean_raw_bytes_u8, huffman_encode_mean_picos)
    );
    println!(
        "{:<15} | {:>12.2} | {:>12.2} | {:>14.1}",
        "8th-Bit Token",
        cc_picos_to_nanos_f64(tokenize_encode_mean_picos),
        cc_picos_to_nanos_f64(cc_mean_picos(tokenize_decode_picos_sum, timed_row_count)),
        cc_megabytes_per_second(mean_raw_bytes_u8, tokenize_encode_mean_picos)
    );

    println!("{CC_REPORT_THIN_LINE}");
    println!(
        " Measurement phase wall-clock : {:>10.3} s",
        measurement_elapsed_duration.as_secs_f64()
    );
    println!(
        " Total program wall-clock     : {:>10.3} s",
        program_started_instant.elapsed().as_secs_f64()
    );
    println!(
        " Supervisory re-initializations: {}",
        supervisory_reboot_count
    );
    if any_resolution_suspect {
        println!(
            " (*) At least one measurement recorded zero elapsed time: clock resolution may be"
        );
        println!(
            "     insufficient, or the operation was eliminated. Increase CC_TIMING_ITERATIONS_PER_BATCH."
        );
    }
    println!("{CC_REPORT_RULE_LINE}");
    println!(" Benchmark complete. Mode & Case-Handling invariants preserved across all runs.");
    println!("{CC_REPORT_RULE_LINE}");

    Ok(())
}
