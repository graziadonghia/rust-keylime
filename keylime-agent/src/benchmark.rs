// src/benchmark.rs

use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn log_metric(
    tpm_ms: u128, 
    ima_read_ms: u128, // <--- NEW PARAMETER
    pq_ms: u128, 
    ima_count: u64, 
    classical_alg: &str, 
    pq_alg: &str
) {
    let file_path = "/tmp/agent_metrics.csv";
    
    // 1. Get timestamp
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs();

    // 2. Open file
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_path)
        .expect("Unable to open benchmark CSV file");

    // 3. Write header
    if file.metadata().unwrap().len() == 0 {
        let _ = writeln!(
            file, 
            "timestamp_unix,classical_alg,pq_alg,tpm_quote_ms,ima_read_ms,pq_latency_ms,ratio,ima_entries"
        );
    }

    // 4. Calculate Ratio (PQ / TPM)
    let ratio = if tpm_ms > 0 { (tpm_ms + pq_ms) as f64 / tpm_ms as f64 } else { 0.0 };

    // 5. Write data
    let _ = writeln!(
        file, 
        "{},{},{},{},{},{:.7},{:.7},{}", 
        since_the_epoch, classical_alg, pq_alg, tpm_ms, ima_read_ms, pq_ms, ratio, ima_count
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