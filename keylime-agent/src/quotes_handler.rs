// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use std::mem;
use crate::common::JsonWrapper;
use crate::crypto;
use crate::serialization::serialize_maybe_base64;
use crate::{tpm, Error as KeylimeError, QuoteData};
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use base64::{engine::general_purpose, Engine as _};
use quantcrypt::dsas::DsaAlgorithm;
use quantcrypt::dsas::DsaKeyGenerator;
use quantcrypt::keys::PrivateKey;
use std::any::Any;
use log::*;
use serde::{Deserialize, Serialize};
use std::{
    fs::{read, read_to_string},
    io::{Read, Seek},
};
use std::fs::OpenOptions;
use std::sync::atomic::Ordering;

use std::io::Write;
use tss_esapi::structures::PcrSlot;
use crate::benchmark;


#[derive(Deserialize)]
pub struct Ident {
    nonce: String,
}

#[derive(Deserialize)]
pub struct Integ {
    nonce: String,
    mask: String,
    partial: String,
    ima_ml_entry: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub(crate) struct KeylimeQuote {
    pub quote: String, // 'r' + quote + sig + pcrblob
    pub hash_alg: String,
    pub enc_alg: String,
    pub sign_alg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ima_measurement_list: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mb_measurement_list: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ima_measurement_list_entry: Option<u64>,
}


#[derive(Serialize, Deserialize, Debug, Default)]
pub(crate) struct PQquote {
    pub pq_algorithm: String,
    pub pq_wrap_signature: Vec<u8>, 
    pub pq_wrap_signature_len: usize,
    pub quote_len: usize,
    pub quote: String,              
    pub hash_alg: String,           
    pub enc_alg: String,            
    pub sign_alg: String,           
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<String>,      
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ima_measurement_list: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mb_measurement_list: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ima_measurement_list_entry: Option<u64>, 
}

// function to send quote to kernel for PQ wrap
fn get_pq_signature_for_quote(quote_str: &str) -> Result<Vec<u8>, KeylimeError> {
    const DEV_PATH: &str = "/dev/qubip.quote";
    const SIG_PATH: &str = "/proc/qubip_pq_quote.sig.bin";

    // 1) Write the quote to /dev/qubip.quote (kernel signs it)
    let mut dev = OpenOptions::new()
        .write(true)
        .open(DEV_PATH)
        .map_err(|e| {
            KeylimeError::Other(format!(
                "FATAL: cannot open {} for PQ wrapping – kernel module missing or wrong permissions: {}",
                DEV_PATH, e
            ))
    })?;

    dev.write_all(quote_str.as_bytes())
        .map_err(|e| {
            KeylimeError::Other(format!(
                "FATAL: Failed to write TPM quote to {} - kernel module may be unloaded: {}",
                DEV_PATH, e
            ))
        })?;

    // 2) Read the resulting PQ signature from /proc/qubip_pq_quote.sig.bin
    let sig = read(SIG_PATH).map_err(|e| {
        KeylimeError::Other(format!(
            "FATAL: Failed to read PQ signature from {} - module not functioning: {}",
            SIG_PATH, e
        ))
    })?;

    if sig.is_empty() {
        return Err(KeylimeError::Other(format!(
            "FATAL: PQ signature from {} is empty – invalid module response",
            SIG_PATH
        )));
    }

    debug!("PQ signature length: {} bytes", sig.len());
    Ok(sig)
}

// This is a Quote request from the tenant, which does not check
// integrity measurement. It should return this data:
// { QuoteAIK(nonce, 16:H(NK_pub)), NK_pub }
pub async fn identity(
    req: HttpRequest,
    param: web::Query<Ident>,
    data: web::Data<QuoteData>,
) -> impl Responder {
    // nonce can only be in alphanumerical format
    if !param.nonce.chars().all(char::is_alphanumeric) {
        warn!("Get quote returning 400 response. Parameters should be strictly alphanumeric: {}", param.nonce);
        return HttpResponse::BadRequest().json(JsonWrapper::error(
            400,
            format!(
                "Parameters should be strictly alphanumeric: {}",
                param.nonce
            ),
        ));
    }

    if param.nonce.len() > tpm::MAX_NONCE_SIZE {
        warn!("Get quote returning 400 response. Nonce is too long (max size {}): {}",
              tpm::MAX_NONCE_SIZE,
              param.nonce.len()
        );
        return HttpResponse::BadRequest().json(JsonWrapper::error(
            400,
            format!(
                "Nonce is too long (max size {}): {}",
                tpm::MAX_NONCE_SIZE,
                param.nonce
            ),
        ));
    }

    debug!("Calling Identity Quote with nonce: {}", param.nonce);

    // must unwrap here due to lock mechanism
    // https://github.com/rust-lang-nursery/failure/issues/192
    let mut context = data.tpmcontext.lock().unwrap(); //#[allow_ci]

    let tpm_quote = match context.quote(
        param.nonce.as_bytes(),
        0,
        &data.pub_key,
        data.ak_handle,
        data.hash_alg,
        data.sign_alg,
    ) {
        Ok(quote) => quote,
        Err(e) => {
            debug!("Unable to retrieve quote: {:?}", e);
            return HttpResponse::InternalServerError().json(
                JsonWrapper::error(
                    500,
                    "Unable to retrieve quote".to_string(),
                ),
            );
        }
    };

    let mut quote = KeylimeQuote {
        quote: tpm_quote,
        hash_alg: data.hash_alg.to_string(),
        enc_alg: data.enc_alg.to_string(),
        sign_alg: data.sign_alg.to_string(),
        ..Default::default()
    };

    match crypto::pkey_pub_to_pem(&data.pub_key) {
        Ok(pubkey) => quote.pubkey = Some(pubkey),
        Err(e) => {
            debug!("Unable to retrieve public key for quote: {:?}", e);
            return HttpResponse::InternalServerError().json(
                JsonWrapper::error(
                    500,
                    "Unable to retrieve quote".to_string(),
                ),
            );
        }
    }

    // Conversione del campo quote in CString
    let quote_ptr: *const u8 = quote.quote.as_ptr() as *const u8;

    fn print_type_of<T>(_: &T) {
        debug!("{}", std::any::type_name::<T>());
    }
    let pq_sig = match get_pq_signature_for_quote(&quote.quote) {
        Ok(sig) => sig,
        Err(e) => {
            error!("Kernel PQ-wrap module failure: {:?}", e);
            return HttpResponse::InternalServerError().json(
                JsonWrapper::error(
                    500,
                    format!("Critical error: unable to perform PQ wrap – {}", e),
                ),
            );
        }
    };


    let pq_quote = PQquote {
        pq_algorithm: data.pq_algorithm.clone(),
        pq_wrap_signature: pq_sig.clone(),
        pq_wrap_signature_len: pq_sig.len(),
        quote_len: quote.quote.len(),
        quote: quote.quote,
        hash_alg: quote.hash_alg,
        enc_alg: quote.enc_alg,
        sign_alg: quote.sign_alg,
        pubkey: quote.pubkey,
        ima_measurement_list: quote.ima_measurement_list,
        mb_measurement_list: quote.mb_measurement_list,
        ima_measurement_list_entry: quote.ima_measurement_list_entry,
    };
    // Log the entire quote content
    //info!("PQ signature: {:?}", pq_quote.pq_wrap_signature);
    let response = JsonWrapper::success(pq_quote);
    info!("GET integrity quote returning 200 response");
    HttpResponse::Ok().json(response)
}

// This is a Quote request from the cloud verifier, which will check
// integrity measurement. The PCRs included in the Quote will be specified
// by the mask. It should return this data:
// { QuoteAIK(nonce, 16:H(NK_pub), xi:yi), NK_pub}
// where xi:yi are additional PCRs to be included in the quote.
fn filter_measurements_by_path(
    measurements: &str,
    paths: &[&str],
) -> String {
    info!("Filtering measurements for paths: {:?}", paths);
    let filtered: Vec<&str> = measurements
        .lines()
        .filter(|line| paths.iter().any(|path|line.contains(path)))
        .collect();
    info!("Number of measurements after filtering: {}", filtered.len());
    filtered.join("\n")
}
pub async fn integrity(
    req: HttpRequest,
    param: web::Query<Integ>,
    data: web::Data<QuoteData>,
) -> impl Responder {
    // nonce, mask can only be in alphanumerical format
    if !param.nonce.chars().all(char::is_alphanumeric) {
        warn!("Get quote returning 400 response. Parameters should be strictly alphanumeric: {}", param.nonce);
        return HttpResponse::BadRequest().json(JsonWrapper::error(
            400,
            format!("nonce should be strictly alphanumeric: {}", param.nonce),
        ));
    }

    if !param.mask.chars().all(char::is_alphanumeric) {
        warn!("Get quote returning 400 response. Parameters should be strictly alphanumeric: {}", param.mask);
        return HttpResponse::BadRequest().json(JsonWrapper::error(
            400,
            format!("mask should be strictly alphanumeric: {}", param.mask),
        ));
    }

    let mask =
        match u32::from_str_radix(param.mask.trim_start_matches("0x"), 16) {
            Ok(mask) => mask,
            Err(e) => {
                return HttpResponse::BadRequest().json(JsonWrapper::error(
                    400,
                    format!(
                        "mask should be a hex encoded 32-bit integer: {}",
                        param.mask
                    ),
                ));
            }
        };

    if param.nonce.len() > tpm::MAX_NONCE_SIZE {
        warn!("Get quote returning 400 response. Nonce is too long (max size {}): {}",
              tpm::MAX_NONCE_SIZE,
              param.nonce.len()
        );
        return HttpResponse::BadRequest().json(JsonWrapper::error(
            400,
            format!(
                "Nonce is too long (max size: {}): {}",
                tpm::MAX_NONCE_SIZE,
                param.nonce.len()
            ),
        ));
    }

    // If partial="0", include the public key in the quote
    let pubkey = match &param.partial[..] {
        "0" => {
            let pubkey = match crypto::pkey_pub_to_pem(&data.pub_key) {
                Ok(pubkey) => pubkey,
                Err(e) => {
                    debug!("Unable to retrieve public key: {:?}", e);
                    return HttpResponse::InternalServerError().json(
                        JsonWrapper::error(
                            500,
                            "Unable to retrieve public key".to_string(),
                        ),
                    );
                }
            };
            Some(pubkey)
        }
        "1" => None,
        _ => {
            warn!("Get quote returning 400 response. uri must contain key 'partial' and value '0' or '1'");
            return HttpResponse::BadRequest().json(JsonWrapper::error(
                400,
                "uri must contain key 'partial' and value '0' or '1'"
                    .to_string(),
            ));
        }
    };

    debug!(
        "Calling Integrity Quote with nonce: {}, mask: {}",
        param.nonce, param.mask
    );

    // If an index was provided, the request is for the entries starting from the given index
    // (iterative attestation). Otherwise the request is for the whole list.
    let nth_entry = match &param.ima_ml_entry {
        None => 0,
        Some(idx) => idx.parse::<u64>().unwrap_or(0),
    };

    // must unwrap here due to lock mechanism
    // https://github.com/rust-lang-nursery/failure/issues/192
    let mut context = data.tpmcontext.lock().unwrap(); //#[allow_ci]

    // Generate the ID quote.

    // --------------------------------------------
    // 1. TPM quote
    // --------------------------------------------
    let tpm_start = std::time::Instant::now();
    let tpm_quote = match context.quote(
        param.nonce.as_bytes(),
        mask,
        &data.pub_key,
        data.ak_handle,
        data.hash_alg,
        data.sign_alg,
    ) {
        Ok(tpm_quote) => tpm_quote,
        Err(e) => {
            debug!("Unable to retrieve quote: {:?}", e);
            return HttpResponse::InternalServerError().json(
                JsonWrapper::error(
                    500,
                    "Unable to retrieve quote".to_string(),
                ),
            );
        }
    };
    let tpm_duration_ms = tpm_start.elapsed().as_millis();
    debug!("TPM quote generated successfully in {:?} ms", tpm_duration_ms);
    let id_quote = KeylimeQuote {
        quote: tpm_quote,
        hash_alg: data.hash_alg.to_string(),
        enc_alg: data.enc_alg.to_string(),
        sign_alg: data.sign_alg.to_string(),
        ..Default::default()
    };

    // If PCR 0 is included in the mask, obtain the measured boot
    let mut mb_measurement_list = None;
    match tpm::check_mask(mask, &PcrSlot::Slot0) {
        Ok(true) => {
            if let Some(measuredboot_ml_file) = &data.measuredboot_ml_file {
                let mut ml = Vec::<u8>::new();
                let mut f = measuredboot_ml_file.lock().unwrap(); //#[allow_ci]
                if let Err(e) = f.rewind() {
                    debug!("Failed to rewind measured boot file: {}", e);
                    return HttpResponse::InternalServerError().json(
                        JsonWrapper::error(
                            500,
                            "Unable to retrieve quote".to_string(),
                        ),
                    );
                }
                mb_measurement_list = match f.read_to_end(&mut ml) {
                    Ok(_) => Some(general_purpose::STANDARD.encode(ml)),
                    Err(e) => {
                        warn!("Could not read TPM2 event log: {}", e);
                        None
                    }
                };
            }
        }
        Err(e) => {
            debug!("Unable to check PCR mask: {:?}", e);
            return HttpResponse::InternalServerError().json(
                JsonWrapper::error(
                    500,
                    "Unable to retrieve quote".to_string(),
                ),
            );
        }
        _ => (),
    }

    // --------------------------------------------
    // 2. IMA measurement list
    // --------------------------------------------
    debug!("Generating measurement list");
    let ima_start = std::time::Instant::now();
    // Generate the measurement list
    let (ima_measurement_list, ima_measurement_list_entry, num_entries) =
        if let Some(ima_file) = &data.ima_ml_file {
            let mut ima_ml = data.ima_ml.lock().unwrap(); //#[allow_ci]
            match ima_ml.read(
                &mut ima_file.lock().unwrap(), //#[allow_ci]
                nth_entry,
            ) {
                Ok(result) => {
                    (Some(result.0), Some(result.1), Some(result.2))
                }
                Err(e) => {
                    debug!("Unable to read measurement list: {:?}", e);
                    return HttpResponse::InternalServerError().json(
                        JsonWrapper::error(
                            500,
                            "Unable to retrieve quote".to_string(),
                        ),
                    );
                }
            }
        } else {
            (None, None, None)
        };

    let ima_read_duration_ms = ima_start.elapsed().as_millis();
    debug!("Measurement list generated successfully in {:?} ms. Number of entries: {:?}", ima_read_duration_ms, num_entries);
    let ima_count_metric = num_entries.unwrap_or(0);

    // Generate the final quote based on the ID quote
    let quote = KeylimeQuote {
        pubkey,
        ima_measurement_list,
        mb_measurement_list,
        ima_measurement_list_entry,
        ..id_quote
    };
    debug!("Final quote generated successfully");
    // --------------------------------------------
    // 3. PQ wrap
    // --------------------------------------------
    debug!("Generating PQ signature for quote");
    let pq_start = std::time::Instant::now();
    let pq_sig = match get_pq_signature_for_quote(&quote.quote) {
        Ok(sig) => sig,
        Err(e) => {
            debug!("Unable to retrieve PQ signature for quote: {:?}", e);
            return HttpResponse::InternalServerError().json(
                JsonWrapper::error(
                    500,
                    "Unable to retrieve quote".to_string(),
                ),
            );
        }
    };
    // express duration in microseconds
    let pq_duration_us = pq_start.elapsed().as_micros();

    let pq_quote = PQquote {
        pq_algorithm: data.pq_algorithm.clone(),
        pq_wrap_signature: pq_sig.clone(),
        pq_wrap_signature_len: pq_sig.len(),
        quote_len: quote.quote.len(),
        quote: quote.quote,
        hash_alg: quote.hash_alg,
        enc_alg: quote.enc_alg,
        sign_alg: quote.sign_alg,
        pubkey: quote.pubkey,
        ima_measurement_list: quote.ima_measurement_list.clone(),
        mb_measurement_list: quote.mb_measurement_list.clone(),
        ima_measurement_list_entry: quote.ima_measurement_list_entry,
    };

    debug!("PQ signature generated successfully in {:?} us", pq_duration_us);
    // --------------------------------------------
    // 4. Log benchmark metrics
    // --------------------------------------------

    // increment the atomic counter
    let current_cycle = data.request_counter.fetch_add(1, Ordering::SeqCst) + 1;
    info!("Remote attestation cycle count: {}", current_cycle);


    let classical_alg = data.sign_alg.to_string();
    let pq_alg = data.pq_algorithm.to_string();
    benchmark::log_metric(
        current_cycle,
        tpm_duration_ms,
        ima_read_duration_ms,
        pq_duration_us,
        ima_count_metric,
        &classical_alg,
        &pq_alg,
    );
    // [Optional] Log info to console so you know when 1000 is reached
    if current_cycle == 1000 {
        info!("*** TEST COMPLETE: 1000 Cycles Reached ***");
    }
    // Printing each field
    info!("Size of quote = {} bytes", size_of::<PQquote>().to_string());
    info!("Size of PQ signature = {} bytes", pq_quote.pq_wrap_signature_len.to_string());
    info!("Quote Length = {} bytes", pq_quote.quote_len.to_string());
    let response = JsonWrapper::success(pq_quote);
    info!("GET integrity quote returning 200 response");
    info!("Send integrity quote to the verifier");
    HttpResponse::Ok().json(response)
}

#[cfg(feature = "testing")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::API_VERSION;
    use actix_web::{test, web, App};
    use keylime::{crypto::testing::pkey_pub_from_pem, tpm};

    #[actix_rt::test]
    async fn test_identity() {
        let quotedata = web::Data::new(QuoteData::fixture().unwrap()); //#[allow_ci]
        let mut app =
            test::init_service(App::new().app_data(quotedata.clone()).route(
                &format!("/{API_VERSION}/quotes/identity"),
                web::get().to(identity),
            ))
            .await;

        let req = test::TestRequest::get()
            .uri(&format!(
                "/{API_VERSION}/quotes/identity?nonce=1234567890ABCDEFHIJ",
            ))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let result: JsonWrapper<KeylimeQuote> =
            test::read_body_json(resp).await;
        assert_eq!(result.results.hash_alg.as_str(), "sha256");
        assert_eq!(result.results.enc_alg.as_str(), "rsa");
        assert_eq!(result.results.sign_alg.as_str(), "rsassa");
        assert!(
            pkey_pub_from_pem(&result.results.pubkey.unwrap()) //#[allow_ci]
                .unwrap() //#[allow_ci]
                .public_eq(&quotedata.pub_key)
        );
        assert!(result.results.quote.starts_with('r'));

        let mut context = quotedata.tpmcontext.lock().unwrap(); //#[allow_ci]
        tpm::testing::check_quote(
            context.as_mut(),
            quotedata.ak_handle,
            &result.results.quote,
            b"1234567890ABCDEFHIJ",
        )
        .expect("unable to verify quote");
    }

    #[actix_rt::test]
    async fn test_integrity_pre() {
        let quotedata = web::Data::new(QuoteData::fixture().unwrap()); //#[allow_ci]
        let mut app =
            test::init_service(App::new().app_data(quotedata.clone()).route(
                &format!("/{API_VERSION}/quotes/integrity"),
                web::get().to(integrity),
            ))
            .await;

        let req = test::TestRequest::get()
            .uri(&format!(
                "/{API_VERSION}/quotes/integrity?nonce=1234567890ABCDEFHIJ&mask=0x408000&partial=0",
            ))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let result: JsonWrapper<KeylimeQuote> =
            test::read_body_json(resp).await;
        assert_eq!(result.results.hash_alg.as_str(), "sha256");
        assert_eq!(result.results.enc_alg.as_str(), "rsa");
        assert_eq!(result.results.sign_alg.as_str(), "rsassa");
        assert!(
            pkey_pub_from_pem(&result.results.pubkey.unwrap()) //#[allow_ci]
                .unwrap() //#[allow_ci]
                .public_eq(&quotedata.pub_key)
        );

        if let Some(ima_mutex) = &quotedata.ima_ml_file {
            let mut ima_ml_file = ima_mutex.lock().unwrap(); //#[allow_ci]
            ima_ml_file.rewind().unwrap(); //#[allow_ci]
            let mut ima_ml = String::new();
            match ima_ml_file.read_to_string(&mut ima_ml) {
                Ok(_) => {
                    assert_eq!(
                        result.results.ima_measurement_list.unwrap().as_str(), //#[allow_ci]
                        ima_ml
                    );
                    assert!(result.results.quote.starts_with('r'));

                    let mut context = quotedata.tpmcontext.lock().unwrap(); //#[allow_ci]
                    tpm::testing::check_quote(
                        context.as_mut(),
                        quotedata.ak_handle,
                        &result.results.quote,
                        b"1234567890ABCDEFHIJ",
                    )
                    .expect("unable to verify quote");
                }
                Err(e) => panic!("Could not read IMA file: {e}"), //#[allow_ci]
            }
        } else {
            panic!("IMA file was None"); //#[allow_ci]
        }
    }

    #[actix_rt::test]
    async fn test_integrity_post() {
        let quotedata = web::Data::new(QuoteData::fixture().unwrap()); //#[allow_ci]
        let mut app =
            test::init_service(App::new().app_data(quotedata.clone()).route(
                &format!("/{API_VERSION}/quotes/integrity"),
                web::get().to(integrity),
            ))
            .await;

        let req = test::TestRequest::get()
            .uri(&format!(
                "/{API_VERSION}/quotes/integrity?nonce=1234567890ABCDEFHIJ&mask=0x408000&partial=1",
            ))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let result: JsonWrapper<KeylimeQuote> =
            test::read_body_json(resp).await;
        assert_eq!(result.results.hash_alg.as_str(), "sha256");
        assert_eq!(result.results.enc_alg.as_str(), "rsa");
        assert_eq!(result.results.sign_alg.as_str(), "rsassa");

        if let Some(ima_mutex) = &quotedata.ima_ml_file {
            let mut ima_ml_file = ima_mutex.lock().unwrap(); //#[allow_ci]
            ima_ml_file.rewind().unwrap(); //#[allow_ci]
            let mut ima_ml = String::new();
            match ima_ml_file.read_to_string(&mut ima_ml) {
                Ok(_) => {
                    assert_eq!(
                        result.results.ima_measurement_list.unwrap().as_str(), //#[allow_ci]
                        ima_ml
                    );
                    assert!(result.results.quote.starts_with('r'));
                }
                Err(e) => panic!("Could not read IMA file: {e}"), //#[allow_ci]
            }
        } else {
            panic!("IMA file was None"); //#[allow_ci]
        }

        let mut context = quotedata.tpmcontext.lock().unwrap(); //#[allow_ci]
        tpm::testing::check_quote(
            context.as_mut(),
            quotedata.ak_handle,
            &result.results.quote,
            b"1234567890ABCDEFHIJ",
        )
        .expect("unable to verify quote");
    }

    #[actix_rt::test]
    async fn test_missing_ima_file() {
        let mut quotedata = QuoteData::fixture().unwrap(); //#[allow_ci]
                                                           // Remove the IMA log file from the context
        quotedata.ima_ml_file = None;
        let data = web::Data::new(quotedata);
        let mut app =
            test::init_service(App::new().app_data(data.clone()).route(
                &format!("/{API_VERSION}/quotes/integrity"),
                web::get().to(integrity),
            ))
            .await;

        let req = test::TestRequest::get()
            .uri(&format!(
                "/{API_VERSION}/quotes/integrity?nonce=1234567890ABCDEFHIJ&mask=0x408000&partial=0",
            ))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let result: JsonWrapper<KeylimeQuote> =
            test::read_body_json(resp).await;
        assert!(result.results.ima_measurement_list.is_none());
        assert!(result.results.ima_measurement_list_entry.is_none());
    }
}
