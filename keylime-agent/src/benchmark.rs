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
    pq_alg: &str
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
            "cycle,timestamp_unix,classical_alg,pq_alg,tpm_quote_ms,ima_read_ms,pq_latency_us,total_hybrid_ms,ratio,ima_entries"
        );
    }

    // 4. Calculate Stats
    // Hybrid Time = TPM (Classical) + PQ Wrap
    let pq_ms = pq_us / 1000; // Convert microseconds to milliseconds
    let total_hybrid_ms = tpm_ms as f64 + (pq_ms as f64 / 1000.0) ;
    
    // Ratio = Hybrid / Classical
    let ratio = if tpm_ms > 0 { total_hybrid_ms as f64 / tpm_ms as f64 } else { 0.0 };

    // 5. Write data (Include cycle and total_hybrid_ms)
    let _ = writeln!(
        file, 
        "{},{},{},{},{},{},{},{},{:.10},{}", 
        cycle, since_the_epoch, classical_alg, pq_alg, tpm_ms, ima_read_ms, pq_us, total_hybrid_ms, ratio, ima_count
    );
}