// src/benchmark.rs

use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn log_metric(
    cycle: usize,          // <--- 1. NEW PARAMETER to count the attestation cycles
    tpm_ms: u128, 
    ima_read_ms: u128,
    pq_us: u128, 
    ima_count: u64, 
    classical_alg: &str, 
    pq_alg: &str,
    total_agent_latency_classical_ms: u128,
    total_agent_latency_ms: u128,
    tpm_quote_len: usize,
    classical_pubkey_len: usize,
    pq_pubkey_len: usize,
    ima_log_len: usize,
    pq_sig_len: usize,
) {

    let file_path = "/tmp/qubip_3_1_agent_metrics.csv";
    
    // 1. Get timestamp
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs();

    // 2. Open file
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_path)
        .expect("Unable to open benchmark CSV file");

    // 3. Write header (Update header string)
    if file.metadata().unwrap().len() == 0 {
        let _ = writeln!(
            file, 
            "cycle,timestamp_unix,classical_alg,pq_alg,tpm_quote_ms,ima_read_ms,pq_latency_us,total_hybrid_ms,ratio,ima_entries,total_agent_latency_classical_ms,total_agent_latency_ms,tpm_quote_len,classical_pubkey_len,pq_pubkey_len,ima_log_len,pq_sig_len,"
        );
    }

    // 4. Calculate Stats
    // Hybrid Time = TPM (Classical) + PQ Wrap
    let pq_ms = pq_us / 1000; // Convert microseconds to milliseconds
    let total_ms = tpm_ms as f64 + (pq_ms as f64 / 1000.0) ;
    
    // Ratio = Hybrid / Classical
    let ratio = if tpm_ms > 0 { total_ms / tpm_ms as f64 } else { 0.0 };
    // 5. Write data (Include cycle and total_ms)
    let _ = writeln!(
        file, 
        "{},{},{},{},{},{},{},{:.10},{:.10},{},{:.10},{:.10},{},{},{},{},{}", 
        cycle, since_the_epoch, classical_alg, pq_alg, tpm_ms, ima_read_ms, pq_us, total_ms, ratio, ima_count, total_agent_latency_classical_ms, total_agent_latency_ms, tpm_quote_len, classical_pubkey_len, pq_pubkey_len, ima_log_len, pq_sig_len
    );
}

/// Appends a registration event to the CSV file.
/// Columns: timestamp, pq_algo, pq_sign_us, tpm_activate_ms, net_reg_ms, net_activate_ms, total_ms
pub fn log_registration(
    pq_sign_us: u128,
    tpm_activate_ms: u128,
    net_reg_ms: u128,
    net_activate_ms: u128,
    total_ms: u128,
    pq_alg: &str
) {
    let file_path = "/tmp/agent_registration.csv";
    
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs();

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_path)
        .expect("Unable to open registration CSV file");

    if file.metadata().unwrap().len() == 0 {
        let _ = writeln!(
            file, 
            "timestamp_unix,pq_alg,pq_sign_us,tpm_activate_ms,net_reg_ms,net_activate_ms,total_reg_ms"
        );
    }

    let _ = writeln!(
        file, 
        "{},{},{},{},{},{},{}", 
        since_the_epoch, pq_alg, pq_sign_us, tpm_activate_ms, net_reg_ms, net_activate_ms, total_ms
    );
}