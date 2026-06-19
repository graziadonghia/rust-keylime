// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

#![deny(
    nonstandard_style,
    dead_code,
    improper_ctypes,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    unconditional_recursion,
    unused,
    while_true,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_allocation,
    unused_comparisons,
    unused_parens,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
// Temporarily allow these until they can be fixed
//  unused: there is a lot of code that's for now unused because this codebase is still in development
//  missing_docs: there is many functions missing documentations for now
#![allow(unused, missing_docs)]

mod agent_handler;
mod common;
mod config;
mod error;
mod errors_handler;
mod keys_handler;
mod notifications_handler;
mod payloads;
mod permissions;
mod quotes_handler;
mod registrar_agent;
mod revocation;
mod secure_mount;
mod serialization;
mod version_handler;
mod benchmark;

use actix_web::{dev::Service, http, middleware, rt, web, App, HttpServer};
use std::sync::atomic::{AtomicUsize, Ordering};
use base64::{engine::general_purpose, Engine as _};
use clap::{Arg, Command as ClapApp};
use common::*;
use std::fs::OpenOptions;
use std::{
    fs::{read, read_to_string},
    io::Seek,
};
use std::time::{SystemTime, UNIX_EPOCH, Instant};
use error::{Error, Result};
use futures::{
    future::{ok, TryFutureExt},
    try_join,
};
use keylime::{
    crypto, crypto::x509::CertificateBuilder, ima::MeasurementList,
    list_parser::parse_list, tpm,
};
use log::*;
use openssl::{
    pkey::{PKey, Private, Public},
    x509::X509,
};
use std::{
    convert::TryFrom,
    fs,
    io::{BufReader, Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Mutex,
    time::Duration,
    os::raw::c_uchar,
    ptr,
    os::raw::c_char, 
    os::raw::c_ulong
};
use tokio::{
    signal::unix::{signal, SignalKind},
    sync::{mpsc, oneshot},
};
use tss_esapi::{
    handles::KeyHandle,
    interface_types::algorithm::{AsymmetricAlgorithm, HashingAlgorithm},
    interface_types::resource_handles::Hierarchy,
    structures::{Auth, Data, Digest, MaxBuffer, PublicBuffer},
    traits::Marshall,
    Context,
};
use uuid::Uuid;

use libc::size_t;

use std::ffi::CString;
use quantcrypt::dsas::DsaAlgorithm;
use quantcrypt::dsas::DsaKeyGenerator;
use quantcrypt::keys::PrivateKey;

use std::process::{Command, Stdio};

#[macro_use]
extern crate static_assertions;

static NOTFOUND: &[u8] = b"Not Found";

// This data is passed in to the actix httpserver threads that
// handle quotes.
#[derive(Debug)]
pub struct QuoteData {
    tpmcontext: Mutex<tpm::Context>,
    priv_key: PKey<Private>,
    pub_key: PKey<Public>,
    ak_handle: KeyHandle,
    payload_tx: mpsc::Sender<payloads::PayloadMessage>,
    revocation_tx: mpsc::Sender<revocation::RevocationMessage>,
    keys_tx: mpsc::Sender<(
        keys_handler::KeyMessage,
        Option<oneshot::Sender<keys_handler::SymmKeyMessage>>,
    )>,
    hash_alg: keylime::algorithms::HashAlgorithm,
    enc_alg: keylime::algorithms::EncryptionAlgorithm,
    sign_alg: keylime::algorithms::SignAlgorithm,
    agent_uuid: String,
    allow_payload_revocation_actions: bool,
    secure_size: String,
    work_dir: PathBuf,
    ima_ml_file: Option<Mutex<fs::File>>,
    measuredboot_ml_file: Option<Mutex<fs::File>>,
    ima_ml: Mutex<MeasurementList>,
    secure_mount: PathBuf,
    pq_algorithm: String,
    request_counter: AtomicUsize,

}

#[actix_web::main]
async fn main() -> Result<()> {
    // Print --help information
    let matches = ClapApp::new("keylime_agent")
        .about("A Rust implementation of the Keylime agent")
        .override_usage(
            "sudo RUST_LOG=keylime_agent=trace ./target/debug/keylime_agent",
        )
        .get_matches();

    pretty_env_logger::init();

    // Load config
    let mut config = config::KeylimeConfig::new()?;

    // load path for IMA logfile
    #[cfg(test)]
    fn ima_ml_path_get(_: &String) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-data")
            .join("ima")
            .join("ascii_runtime_measurements")
    }

    #[cfg(not(test))]
    fn ima_ml_path_get(s: &String) -> PathBuf {
        Path::new(&s).to_path_buf()
    }

    let ima_ml_path = ima_ml_path_get(&config.agent.ima_ml_path);

    // check whether anyone has overridden the default
    // if ima_ml_path.as_os_str() != config::DEFAULT_IMA_ML_PATH {
    //     warn!(
    //         "IMA measurement list location override: {}",
    //         ima_ml_path.display()
    //     );
    // }

    // check IMA logfile exists & accessible
    let ima_ml_file = if ima_ml_path.exists() {
        match fs::File::open(&ima_ml_path) {
            Ok(file) => Some(Mutex::new(file)),
            Err(e) => {
                warn!(
                    "IMA measurement list not accessible: {}",
                    ima_ml_path.display()
                );
                None
            }
        }
    } else {
        warn!(
            "IMA measurement list not available: {}",
            ima_ml_path.display()
        );
        None
    };

    // load path for MBA logfile
    let mut measuredboot_ml_path =
        Path::new(&config.agent.measuredboot_ml_path);
    let env_mb_path: String;
    #[cfg(feature = "testing")]
    if let Ok(v) = std::env::var("TPM_BINARY_MEASUREMENTS") {
        env_mb_path = v;
        measuredboot_ml_path = Path::new(&env_mb_path);
    }

    // check whether anyone has overridden the default MBA logfile
    if measuredboot_ml_path.as_os_str()
        != config::DEFAULT_MEASUREDBOOT_ML_PATH
    {
        warn!(
            "Measured boot measurement list location override: {}",
            measuredboot_ml_path.display()
        );
    }

    // check MBA logfile exists & accessible
    let measuredboot_ml_file = if measuredboot_ml_path.exists() {
        match fs::File::open(measuredboot_ml_path) {
            Ok(file) => Some(Mutex::new(file)),
            Err(e) => {
                warn!(
                    "Measured boot measurement list not accessible: {}",
                    measuredboot_ml_path.display()
                );
                None
            }
        }
    } else {
        warn!(
            "Measured boot measurement list not available: {}",
            measuredboot_ml_path.display()
        );
        None
    };

    // The agent cannot run when a payload script is defined, but mTLS is disabled and insecure
    // payloads are not explicitly enabled
    if !config.agent.enable_agent_mtls
        && !config.agent.enable_insecure_payload
        && !config.agent.payload_script.is_empty()
    {
        let message = "The agent mTLS is disabled and 'payload_script' is not empty. To allow the agent to run, 'enable_insecure_payload' has to be set to 'True'".to_string();

        error!("Configuration error: {}", &message);
        return Err(Error::Configuration(message));
    }

    let secure_size = config.agent.secure_size.clone();
    let work_dir = PathBuf::from(&config.agent.keylime_dir);
    let mount = secure_mount::mount(&work_dir, &config.agent.secure_size)?;

    let run_as = if permissions::get_euid() == 0 {
        if (config.agent.run_as).is_empty() {
            warn!("Cannot drop privileges since 'run_as' is empty in 'agent' section of 'keylime-agent.conf'.");
            None
        } else {
            Some(&config.agent.run_as)
        }
    } else {
        error!("Cannot drop privileges: not enough permission");
        return Err(Error::Configuration(
            "Cannot drop privileges: not enough permission".to_string(),
        ));
    };

    // Drop privileges
    if let Some(user_group) = run_as {
        permissions::chown(user_group, &mount)?;
        if let Err(e) = permissions::run_as(user_group) {
            let message = "The user running the Keylime agent should be set in keylime-agent.conf, using the parameter `run_as`, with the format `user:group`".to_string();

            error!("Configuration error: {}", &message);
            return Err(Error::Configuration(message));
        }
        info!("Running the service as {}...", user_group);
    }

    info!("Starting server with API version {}...", API_VERSION);

    let mut ctx = tpm::Context::new()?;

    //  Retrieve the TPM Vendor, this allows us to warn if someone is using a
    // Software TPM ("SW")
    if tss_esapi::utils::get_tpm_vendor(ctx.as_mut())?.contains("SW") {
        warn!("INSECURE: Keylime is currently using a software TPM emulator rather than a real hardware TPM.");
        warn!("INSECURE: The security of Keylime is NOT linked to a hardware root of trust.");
        warn!("INSECURE: Only use Keylime in this mode for testing or debugging purposes.");
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "legacy-python-actions")] {
            warn!("The support for legacy python revocation actions is deprecated and will be removed on next major release");

            let actions_dir = &config.agent.revocation_actions_dir;
            // Verify if the python shim is installed in the expected location
            let python_shim = Path::new(&actions_dir).join("shim.py");
            if !python_shim.exists() {
                error!("Could not find python shim at {}", python_shim.display());
                return Err(Error::Configuration(format!(
                    "Could not find python shim at {}",
                    python_shim.display()
                )));
            }
        }
    }

    // When the tpm_ownerpassword is given, set auth for the Endorsement hierarchy.
    // Note in the Python implementation, tpm_ownerpassword option is also used for claiming
    // ownership of TPM access, which will not be implemented here.
    let tpm_ownerpassword = &config.agent.tpm_ownerpassword;
    if !tpm_ownerpassword.is_empty() {
        let auth = if let Some(hex_ownerpassword) =
            tpm_ownerpassword.strip_prefix("hex:")
        {
            let decoded_ownerpassword =
                hex::decode(hex_ownerpassword).map_err(Error::from)?;
            Auth::try_from(decoded_ownerpassword)?
        } else {
            Auth::try_from(tpm_ownerpassword.as_bytes())?
        };
        ctx.as_mut().tr_set_auth(Hierarchy::Endorsement.into(), auth)
            .map_err(|e| {
                Error::Configuration(format!(
                    "Failed to set TPM context password for Endorsement Hierarchy: {e}"
                ))
            })?;
    };

    let tpm_encryption_alg =
        keylime::algorithms::EncryptionAlgorithm::try_from(
            config.agent.tpm_encryption_alg.as_ref(),
        )?;
    let tpm_hash_alg = keylime::algorithms::HashAlgorithm::try_from(
        config.agent.tpm_hash_alg.as_ref(),
    )?;
    let tpm_signing_alg = keylime::algorithms::SignAlgorithm::try_from(
        config.agent.tpm_signing_alg.as_ref(),
    )?;

    let iak_cert: Option<X509>;
    let idevid_cert: Option<X509>;
    // Attempt to load the IAK and IDevID certificates
    if config.agent.enable_iak_idevid {
        iak_cert = match config.agent.iak_cert.as_ref() {
            "" => {
                debug!("The iak_cert option was not set in the configuration file");
                None
            }
            path => {
                let iak_path = Path::new(&path);
                if iak_path.exists() {
                    debug!(
                        "Loading IAK certificate from {}",
                        iak_path.display()
                    );
                    let iakcert = match crypto::load_x509_der(iak_path) {
                        Ok(cert) => cert,
                        Err(error) => crypto::load_x509_pem(iak_path)?,
                    };
                    Some(iakcert)
                } else {
                    debug!("Can not find IAK certificate");
                    None
                }
            }
        };
        idevid_cert = match config.agent.idevid_cert.as_ref() {
            "" => {
                debug!("The idevid_cert option was not set in the configuration file");
                None
            }
            path => {
                let idevid_path = Path::new(&path);
                if idevid_path.exists() {
                    debug!(
                        "Loading IDevID certificate from {}",
                        idevid_path.display()
                    );
                    let idevcert = match crypto::load_x509_der(idevid_path) {
                        Ok(cert) => cert,
                        Err(error) => crypto::load_x509_pem(idevid_path)?,
                    };
                    Some(idevcert)
                } else {
                    debug!("Can not find IDevID certificate");
                    None
                }
            }
        };
    } else {
        iak_cert = None;
        idevid_cert = None;
    }
    /// Regenerate the IAK and IDevID keys or collect and authorise persisted ones and check that the keys match the certificates that have been loaded
    let (iak, idevid) = if config.agent.enable_iak_idevid {
        /// Try to detect which template has been used by checking the certificate
        let (asym_alg, name_alg) = tpm::get_idevid_template(
            &crypto::match_cert_to_template(
                &iak_cert.clone().ok_or(Error::Other(
                    "IAK/IDevID enabled but cert could not be used"
                        .to_string(),
                ))?,
            )?,
            config.agent.iak_idevid_template.as_str(),
            config.agent.iak_idevid_asymmetric_alg.as_str(),
            config.agent.iak_idevid_name_alg.as_str(),
        )?;

        /// IDevID recreation/collection
        let idevid = if config.agent.idevid_handle.trim().is_empty() {
            /// If handle is not set in config, recreate IDevID according to template
            info!("Recreating IDevID.");
            let regen_idev = ctx.create_idevid(asym_alg, name_alg)?;
            ctx.as_mut().flush_context(regen_idev.handle.into())?;
            // Flush after creating to make room for AK and EK and IAK
            regen_idev
        } else {
            info!("Collecting persisted IDevID.");
            ctx.idevid_from_handle(
                config.agent.idevid_handle.as_str(),
                config.agent.idevid_password.as_str(),
            )?
        };
        /// Check that recreated/collected IDevID key matches the one in the certificate
        if crypto::check_x509_key(
            &idevid_cert.clone().ok_or(Error::Other(
                "IAK/IDevID enabled but IDevID cert could not be used"
                    .to_string(),
            ))?,
            idevid.clone().public,
        )? {
            info!("IDevID matches certificate.");
        } else {
            error!("IDevID template does not match certificate. Check template in configuration.");
            return Err(Error::Configuration("IDevID template does not match certificate. Check template in configuration.".to_string()));
        }

        /// IAK recreation/collection
        let iak = if config.agent.iak_handle.trim().is_empty() {
            /// If handle is not set in config, recreate IAK according to template
            info!("Recreating IAK.");
            ctx.create_iak(asym_alg, name_alg)?
        } else {
            /// If a handle has been set, try to collect from the handle
            /// If there is an IAK password, add the password to the handle
            info!("Collecting persisted IAK.");
            ctx.iak_from_handle(
                config.agent.iak_handle.as_str(),
                config.agent.iak_password.as_str(),
            )?
        };
        /// Check that recreated/collected IAK key matches the one in the certificate
        if crypto::check_x509_key(
            &iak_cert.clone().ok_or(Error::Other(
                "IAK/IDevID enabled but IAK cert could not be used"
                    .to_string(),
            ))?,
            iak.clone().public,
        )? {
            info!("IAK matches certificate.");
        } else {
            error!("IAK template does not match certificate. Check template in configuration.");
            return Err(Error::Configuration("IAK template does not match certificate. Check template in configuration.".to_string()));
        }

        (Some(iak), Some(idevid))
    } else {
        (None, None)
    };

    // Gather EK values and certs
    let ek_result = match config.agent.ek_handle.as_ref() {
        "" => ctx.create_ek(tpm_encryption_alg, None)?,
        s => ctx.create_ek(tpm_encryption_alg, Some(s))?,
    };

    // Calculate the SHA-256 hash of the public key in PEM format
    let ek_hash = hash_ek_pubkey(ek_result.public.clone())?;

    // Replace the uuid with the actual EK hash if the option was set.
    // We cannot do that when the configuration is loaded initially,
    // because only have later access to the the TPM.
    config.agent.uuid = match config.agent.uuid.as_ref() {
        "hash_ek" => ek_hash.clone(),
        s => s.to_string(),
    };
    
    let agent_uuid = config.agent.uuid.clone();

    // Try to load persistent Agent data
    let old_ak = match config.agent.agent_data_path.as_ref() {
        "" => {
            info!("Agent Data path not set in the configuration file");
            None
        }
        path => {
            let path = Path::new(&path);
            if path.exists() {
                match AgentData::load(path) {
                    Ok(data) => {
                        match data.valid(
                            tpm_hash_alg,
                            tpm_signing_alg,
                            ek_hash.as_bytes(),
                        ) {
                            true => {
                                let ak_result = data.get_ak()?;
                                match ctx
                                    .load_ak(ek_result.key_handle, &ak_result)
                                {
                                    Ok(ak_handle) => {
                                        // info!(
                                        //     "Loaded old AK key from {}",
                                        //     path.display()
                                        // );
                                        Some((ak_handle, ak_result))
                                    }
                                    Err(e) => {
                                        warn!(
                                            "Loading old AK key from {} failed: {}",
                                            path.display(),
                                            e
                                        );
                                        None
                                    }
                                }
                            }
                            false => {
                                warn!(
                                    "Not using old {} because it is not valid with current configuration",
                                    path.display()
                                );
                                None
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Could not load agent data: {}", e);
                        None
                    }
                }
            } else {
                info!("Agent Data not found in: {}", path.display());
                None
            }
        }
    };

    // Use old AK or generate a new one and update the AgentData
    let (ak_handle, ak) = match old_ak {
        Some((ak_handle, ak)) => (ak_handle, ak),
        None => {
            let new_ak = ctx.create_ak(
                ek_result.key_handle,
                tpm_hash_alg,
                tpm_signing_alg,
            )?;
            let ak_handle = ctx.load_ak(ek_result.key_handle, &new_ak)?;
            (ak_handle, new_ak)
        }
    };

    // Store new AgentData
    let agent_data_new = AgentData::create(
        tpm_hash_alg,
        tpm_signing_alg,
        &ak,
        ek_hash.as_bytes(),
    )?;

    match config.agent.agent_data_path.as_ref() {
        "" => info!("Agent Data not stored"),
        path => agent_data_new.store(Path::new(&path))?,
    }

    debug!("Hash of TPM's Endorsement Key used as UUID");
    debug!("Agent UUID: {}", agent_uuid);

    let (attest, signature) = if config.agent.enable_iak_idevid {
        let qualifying_data = config.agent.uuid.as_bytes();
        let (attest, signature) = ctx.certify_credential_with_iak(
            Data::try_from(qualifying_data).unwrap(), //#[allow_ci]
            ak_handle,
            iak.as_ref().unwrap().handle, //#[allow_ci]
        )?;
        info!("AK certified with IAK.");

        // // For debugging certify(), the following checks the generated signature
        // let max_b = MaxBuffer::try_from(attest.clone().marshall()?)?;
        // let (hashed_attest, _) = ctx.inner.hash(max_b, HashingAlgorithm::Sha256, Hierarchy::Endorsement,)?;
        // println!("{:?}", hashed_attest);
        // println!("{:?}", signature);
        // println!("{:?}", ctx.inner.verify_signature(iak.as_ref().unwrap().handle, hashed_attest, signature.clone())?); //#[allow_ci]
        (Some(attest), Some(signature))
    } else {
        (None, None)
    };

    // Generate key pair for secure transmission of u, v keys. The u, v
    // keys are two halves of the key used to decrypt the workload after
    // the Identity and Integrity Quotes sent by the agent are validated
    // by the Tenant and Cloud Verifier, respectively.
    //
    // Since we store the u key in memory, discarding this key, which
    // safeguards u and v keys in transit, is not part of the threat model.

    let (nk_pub, nk_priv) = match config.agent.server_key.as_ref() {
        "" => {
            debug!(
                "The server_key option was not set in the configuration file"
            );
            debug!("Generating new key pair");
            crypto::rsa_generate_pair(2048)?
        }
        path => {
            let key_path = Path::new(&path);
            if key_path.exists() {
                // debug!(
                //     "Loading existing key pair from {}",
                //     key_path.display()
                // );
                crypto::load_key_pair(
                    key_path,
                    Some(config.agent.server_key_password.as_ref()),
                )?
            } else {
                debug!("Generating new key pair");
                let (public, private) = crypto::rsa_generate_pair(2048)?;
                // Write the generated key to the file
                crypto::write_key_pair(
                    &private,
                    key_path,
                    Some(config.agent.server_key_password.as_ref()),
                );
                (public, private)
            }
        }
    };

    let cert: X509;
    let mtls_cert;
    let ssl_context;
    if config.agent.enable_agent_mtls {
        let contact_ips = vec![config.agent.contact_ip.as_str()];
        cert = match config.agent.server_cert.as_ref() {
            "" => {
                debug!("The server_cert option was not set in the configuration file");

                crypto::x509::CertificateBuilder::new()
                    .private_key(&nk_priv)
                    .common_name(&agent_uuid)
                    .add_ips(contact_ips)
                    .build()?
            }
            path => {
                let cert_path = Path::new(&path);
                if cert_path.exists() {
                    // debug!(
                    //     "Loading existing mTLS certificate from {}",
                    //     cert_path.display()
                    // );
                    crypto::load_x509_pem(cert_path)?
                } else {
                    debug!("Generating new mTLS certificate");
                    let cert = crypto::x509::CertificateBuilder::new()
                        .private_key(&nk_priv)
                        .common_name(&agent_uuid)
                        .add_ips(contact_ips)
                        .build()?;
                    // Write the generated certificate
                    crypto::write_x509(&cert, cert_path)?;
                    cert
                }
            }
        };


        let trusted_client_ca = match config.agent.trusted_client_ca.as_ref()
        {
            "" => {
                error!("Agent mTLS is enabled, but trusted_client_ca option was not provided");
                return Err(Error::Configuration("Agent mTLS is enabled, but trusted_client_ca option was not provided".to_string()));
            }
            l => l,
        };

        // The trusted_client_ca config option is a list, parse to obtain a vector
        let certs_list = parse_list(trusted_client_ca)?;
        if certs_list.is_empty() {
            error!(
                "Trusted client CA certificate list is empty: could not load any certificate"
            );
            return Err(Error::Configuration(
                "Trusted client CA certificate list is empty: could not load any certificate".to_string()
            ));
        }

        let keylime_ca_certs = match crypto::load_x509_cert_list(
            certs_list.iter().map(Path::new).collect(),
        ) {
            Ok(t) => Ok(t),
            Err(e) => {
                error!("Failed to load trusted CA certificates: {}", e);
                Err(e)
            }
        }?;

        mtls_cert = Some(&cert);
        ssl_context = Some(crypto::generate_tls_context(
            &cert,
            &nk_priv,
            keylime_ca_certs,
        )?);
    } else {
        mtls_cert = None;
        ssl_context = None;
        warn!("mTLS disabled, Tenant and Verifier will reach out to agent via HTTP");
    }


    // retrieve pq algorithm and certificate from config
    let pq_cert_path = Path::new(&config.agent.pq_cert);
    let pq_cert_vec = match read(pq_cert_path) {
        Ok(content) => {
            debug!("Loaded PQ Certificate from {}", pq_cert_path.display());
            content
        },
        Err(e) => {
            error!("Could not load PQ Certificate from {}: {}. Sending empty vector.", pq_cert_path.display(), e);
            Vec::new()
        }
    };

    // should be a string with the algorithm name
    let pq_algorithm = &config.agent.pq_algorithm;
    debug!("PQ Algorithm: {:?}", pq_algorithm);
    debug!("Size of PQ Certificate: {} B", pq_cert_vec.len()); 
    let total_reg_start = Instant::now();
    // Variables to store our metrics
    let mut net_reg_ms: u128 = 0;
    let mut tpm_activate_ms: u128 = 0;
    let mut pq_sign_us: u128 = 0;
    let mut net_activate_ms: u128 = 0;

    {
        // Request keyblob material
        let reg_start = Instant::now();
        let keyblob = if config.agent.enable_iak_idevid {
            let (Some(iak), Some(idevid), Some(attest), Some(signature)) =
                (iak, idevid, attest, signature)
            else {
                error!(
                    "IDevID and IAK are enabled but could not be generated"
                );
                return Err(Error::Configuration(
                    "IDevID and IAK are enabled but could not be generated"
                        .to_string(),
                ));
            };
            registrar_agent::do_register_agent(
                config.agent.registrar_ip.as_ref(),
                config.agent.registrar_port,
                &agent_uuid,
                &PublicBuffer::try_from(ek_result.public.clone())?
                    .marshall()?,
                ek_result.ek_cert,
                &PublicBuffer::try_from(ak.public)?.marshall()?,
                Some(
                    &PublicBuffer::try_from(iak.public.clone())?
                        .marshall()?,
                ),
                Some(
                    &PublicBuffer::try_from(idevid.public.clone())?
                        .marshall()?,
                ),
                idevid_cert,
                iak_cert,
                Some(attest.marshall()?),
                Some(signature.marshall()?),
                mtls_cert,
                config.agent.contact_ip.as_ref(),
                config.agent.contact_port,
                pq_algorithm,
                pq_cert_vec.clone(), // NUOVO ARGOMENTO
            )
            .await?
        } else {
            registrar_agent::do_register_agent(
                config.agent.registrar_ip.as_ref(),
                config.agent.registrar_port,
                &agent_uuid,
                &PublicBuffer::try_from(ek_result.public.clone())?
                    .marshall()?,
                ek_result.ek_cert,
                &PublicBuffer::try_from(ak.public)?.marshall()?,
                None,
                None,
                None,
                None,
                None,
                None,
                mtls_cert,
                config.agent.contact_ip.as_ref(),
                config.agent.contact_port,
                pq_algorithm,
                pq_cert_vec.clone(), // NUOVO ARGOMENTO
            )
            .await?
        };
        net_reg_ms = reg_start.elapsed().as_millis();

        info!("SUCCESS: Agent {} registered", &agent_uuid);
        // measure TPM hardware activation
        info!("Starting Activate Credentials protocol");
        let tpm_start = Instant::now();
        let key = ctx.activate_credential(
            keyblob,
            ak_handle,
            ek_result.key_handle,
        )?;
        tpm_activate_ms = tpm_start.elapsed().as_millis();
        // Flush EK if we created it
        if config.agent.ek_handle.is_empty() {
            ctx.as_mut().flush_context(ek_result.key_handle.into())?;
        }
        let mackey = general_purpose::STANDARD.encode(key.value());

        // auth_tag is the HMAC of the agent UUID using U-Key
        let auth_tag = crypto::compute_hmac(mackey.as_bytes(), agent_uuid.as_bytes())?;
        let auth_tag = hex::encode(&auth_tag);

        //info!("AUTH TAG: {}", auth_tag);
        // measure pq signing
        let sign_start = Instant::now();
        let challenge_sig = match get_pq_signature_for_auth_tag_userspace(&auth_tag) {
            Ok(sig) => sig,
            Err(e) => {
                error!("Kernel PQ-signature module failure: {:?}", e);
                return Err(Error::Other(format!(
                    "Kernel PQ-signature module failure: {:?}",
                    e
                )));
            }
        };
        // print_type_of(&challenge_sig);
        pq_sign_us = sign_start.elapsed().as_micros();
        info!("Computed PQ signature over auth tag");
        debug!("Size of PQ signature over auth tag: {} B", challenge_sig.len()); // should be 4627 B for MLdsa-87
       // info!("PQ SIGNATURE OVER AUTH TAG: {:?}", challenge_sig);
       // measure activation RTT (includes auth tag verification on registrar side)
       let act_start = Instant::now();

        registrar_agent::do_activate_agent(
            config.agent.registrar_ip.as_ref(),
            config.agent.registrar_port,
            &agent_uuid,
            &auth_tag,
            &challenge_sig
            
        )
        .await?;
        net_activate_ms = act_start.elapsed().as_millis();
        info!("SUCCESS: Agent {} activated", &agent_uuid);
    }

    let total_reg_ms = total_reg_start.elapsed().as_millis();
    info!("Registration and Activation performance metrics (in ms):");
    info!("  Network Registration time: {}", net_reg_ms);
    info!("  TPM ActivateCredential time: {}", tpm_activate_ms);
    info!("  PQ Signature time (us): {}", pq_sign_us);
    info!("  Network Activation time: {}", net_activate_ms);
    info!("  Total Registration and Activation time: {}", total_reg_ms);
    // log to CSV
    benchmark::log_registration(
        pq_sign_us,
        tpm_activate_ms,
        net_reg_ms,
        net_activate_ms,
        total_reg_ms,
        pq_algorithm
    );
    /* AGENT REGISTRATION DONE */

    let (mut payload_tx, mut payload_rx) =
        mpsc::channel::<payloads::PayloadMessage>(1);
    let (mut keys_tx, mut keys_rx) = mpsc::channel::<(
        keys_handler::KeyMessage,
        Option<oneshot::Sender<keys_handler::SymmKeyMessage>>,
    )>(1);
    let (mut revocation_tx, mut revocation_rx) =
        mpsc::channel::<revocation::RevocationMessage>(1);

    #[cfg(feature = "with-zmq")]
    let (mut zmq_tx, mut zmq_rx) = mpsc::channel::<revocation::ZmqMessage>(1);

    let revocation_cert = match config.agent.revocation_cert.as_ref() {
        "" => {
            error!(
                "No revocation certificate set in 'revocation_cert' option"
            );
            return Err(Error::Configuration(
                "No revocation certificate set in 'revocation_cert' option"
                    .to_string(),
            ));
        }
        s => PathBuf::from(s),
    };

    let revocation_actions_dir = config.agent.revocation_actions_dir.clone();

    let revocation_actions = match config.agent.revocation_actions.as_ref() {
        "" => None,
        s => Some(s.to_string()),
    };

    let allow_payload_revocation_actions =
        config.agent.allow_payload_revocation_actions;

    let revocation_task = rt::spawn(revocation::worker(
        revocation_rx,
        revocation_cert,
        revocation_actions_dir,
        revocation_actions,
        allow_payload_revocation_actions,
        work_dir.clone(),
        mount.clone(),
    ))
    .map_err(Error::from);

    let quotedata = web::Data::new(QuoteData {
        tpmcontext: Mutex::new(ctx),
        priv_key: nk_priv,
        pub_key: nk_pub,
        ak_handle,
        keys_tx: keys_tx.clone(),
        payload_tx: payload_tx.clone(),
        revocation_tx: revocation_tx.clone(),
        hash_alg: tpm_hash_alg,
        enc_alg: tpm_encryption_alg,
        sign_alg: tpm_signing_alg,
        agent_uuid: agent_uuid.clone(),
        allow_payload_revocation_actions,
        secure_size,
        work_dir,
        ima_ml_file,
        measuredboot_ml_file,
        ima_ml: Mutex::new(MeasurementList::new()),
        secure_mount: PathBuf::from(&mount),
        pq_algorithm: pq_algorithm.clone(),
        // initialize the remote attestation counter
        request_counter: AtomicUsize::new(0),

    });

    let actix_server =
        HttpServer::new(move || {
            App::new()
                .wrap(middleware::ErrorHandlers::new().handler(
                    http::StatusCode::NOT_FOUND,
                    errors_handler::wrap_404,
                ))
                .wrap(middleware::Logger::new(
                    "%r from %a result %s (took %D ms)",
                ))
                .wrap_fn(|req, srv| {
                    info!(
                        "{} invoked from {:?} with uri {}",
                        req.head().method,
                        req.connection_info().peer_addr().unwrap(), //#[allow_ci]
                        req.uri()
                    );
                    srv.call(req)
                })
                .app_data(quotedata.clone())
                .app_data(
                    web::JsonConfig::default()
                        .error_handler(errors_handler::json_parser_error),
                )
                .app_data(
                    web::QueryConfig::default()
                        .error_handler(errors_handler::query_parser_error),
                )
                .app_data(
                    web::PathConfig::default()
                        .error_handler(errors_handler::path_parser_error),
                )
                .service(
                    web::scope(&format!("/{API_VERSION}"))
                        .service(
                            web::scope("/agent")
                                .service(web::resource("/info").route(
                                    web::get().to(agent_handler::info),
                                ))
                                .default_service(web::to(
                                    errors_handler::agent_default,
                                )),
                        )
                        .service(
                            web::scope("/keys")
                                .service(web::resource("/pubkey").route(
                                    web::get().to(keys_handler::pubkey),
                                ))
                                .service(web::resource("/ukey").route(
                                    web::post().to(keys_handler::u_key),
                                ))
                                .service(web::resource("/verify").route(
                                    web::get().to(keys_handler::verify),
                                ))
                                .service(web::resource("/vkey").route(
                                    web::post().to(keys_handler::v_key),
                                ))
                                .default_service(web::to(
                                    errors_handler::keys_default,
                                )),
                        )
                        .service(
                            web::scope("/notifications")
                                .service(web::resource("/revocation").route(
                                    web::post().to(
                                        notifications_handler::revocation,
                                    ),
                                ))
                                .default_service(web::to(
                                    errors_handler::notifications_default,
                                )),
                        )
                        .service(
                            web::scope("/quotes")
                                .service(web::resource("/identity").route(
                                    web::get().to(quotes_handler::identity),
                                ))
                                .service(web::resource("/integrity").route(
                                    web::get().to(quotes_handler::integrity),
                                ))
                                .default_service(web::to(
                                    errors_handler::quotes_default,
                                )),
                        )
                        .default_service(web::to(
                            errors_handler::api_default,
                        )),
                )
                .service(
                    web::resource("/version")
                        .route(web::get().to(version_handler::version)),
                )
                .service(
                    web::resource(r"/v{major:\d+}.{minor:\d+}{tail}*")
                        .to(errors_handler::version_not_supported),
                )
                .default_service(web::to(errors_handler::app_default))
        })
        // Disable default signal handlers.  See:
        // https://github.com/actix/actix-web/issues/2739
        // for details.
        .disable_signals();

    let server;

    // Add bracket if IPv6
    let ip = if config.agent.ip.parse::<IpAddr>()?.is_ipv6() {
        format!("[{}]", config.agent.ip)
    } else {
        config.agent.ip.to_string()
    };
    let port = config.agent.port;
    if config.agent.enable_agent_mtls && ssl_context.is_some() {
        server = actix_server
            .bind_openssl(
                format!("{ip}:{port}"),
                ssl_context.unwrap(), //#[allow_ci]
            )?
            .run();
        info!("Listening on https://{ip}:{port}");
    } else {
        server = actix_server.bind(format!("{ip}:{port}"))?.run();
        info!("Listening on http://{ip}:{port}");
    };

    let server_handle = server.handle();
    let server_task = rt::spawn(server).map_err(Error::from);

    // Only run payload scripts if mTLS is enabled or 'enable_insecure_payload' option is set
    let run_payload = config.agent.enable_agent_mtls
        || config.agent.enable_insecure_payload;

    let payload_task = rt::spawn(payloads::worker(
        config.clone(),
        PathBuf::from(&mount),
        payload_rx,
        revocation_tx.clone(),
        #[cfg(feature = "with-zmq")]
        zmq_tx.clone(),
    ))
    .map_err(Error::from);

    let key_task = rt::spawn(keys_handler::worker(
        run_payload,
        agent_uuid,
        keys_rx,
        payload_tx.clone(),
    ))
    .map_err(Error::from);

    // If with-zmq feature is enabled, run the service listening for ZeroMQ messages
    #[cfg(feature = "with-zmq")]
    let zmq_task = if config.agent.enable_revocation_notifications {
        warn!("The support for ZeroMQ revocation notifications is deprecated and will be removed on next major release");

        let zmq_ip = config.agent.revocation_notification_ip;
        let zmq_port = config.agent.revocation_notification_port;

        rt::spawn(revocation::zmq_worker(
            zmq_rx,
            revocation_tx.clone(),
            zmq_ip,
            zmq_port,
        ))
        .map_err(Error::from)
    } else {
        rt::spawn(ok(())).map_err(Error::from)
    };

    let shutdown_task = rt::spawn(async move {
        let mut sigint = signal(SignalKind::interrupt()).unwrap(); //#[allow_ci]
        let mut sigterm = signal(SignalKind::terminate()).unwrap(); //#[allow_ci]

        tokio::select! {
            _ = sigint.recv() => {
                debug!("Received SIGINT signal");
            },
            _ = sigterm.recv() => {
                debug!("Received SIGTERM signal");
            },
        }

        info!("Shutting down keylime agent");

        // Shutdown tasks
        let server_stop = server_handle.stop(true);
        payload_tx.send(payloads::PayloadMessage::Shutdown);
        keys_tx.send((keys_handler::KeyMessage::Shutdown, None));

        #[cfg(feature = "with-zmq")]
        zmq_tx.send(revocation::ZmqMessage::Shutdown);

        revocation_tx.send(revocation::RevocationMessage::Shutdown);

        // Await tasks shutdown
        server_stop.await;
    })
    .map_err(Error::from);

    // If with-zmq feature is enabled, wait for the service listening for ZeroMQ messages
    #[cfg(feature = "with-zmq")]
    try_join!(zmq_task)?;

    let result = try_join!(
        server_task,
        payload_task,
        key_task,
        revocation_task,
        shutdown_task,
    );
    result.map(|_| ())
}

/*
 * Generates the SLH-DSA signature by calling the external C signer.
 * This keeps the private key completely out of the Rust agent's memory heap.
 */
fn get_pq_signature_for_auth_tag_userspace(auth_tag_str: &str) -> Result<Vec<u8>> {
    // Note: Update this path to wherever you store the compiled C binary.
    debug!("Calling C code to perform SLH-DSA signature");
    const SIGNER_BINARY_PATH: &str = "/usr/local/bin/pq_sign_tss";

    // Spawn the external C signer via sudo (inheriting the Aurora OpenSSL env via -E)
    // Spawn the external C signer natively with explicit OpenSSL paths
    let mut child = Command::new(SIGNER_BINARY_PATH)
        // Explicitly inject the path to your Aurora provider so it never fails to load
        .env("OPENSSL_MODULES", "/opt/quantumsafe/build/lib")
        .env("OPENSSL_CONF", "/opt/quantumsafe/build/ssl/openssl.cnf")
        .env("LD_LIBRARY_PATH", "/opt/quantumsafe/build/lib64:/opt/quantumsafe/build/lib")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            Error::Other(format!(
                "FATAL: Failed to spawn external PQ signer {}: {}",
                SIGNER_BINARY_PATH, e
            ))
        })?;

    // Feed the auth tag payload into the C program's stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(auth_tag_str.as_bytes()).map_err(|e| {
            Error::Other(format!("FATAL: Failed to write to signer stdin: {}", e))
        })?;
    }

    // Wait for the process to finish and collect the output
    let output = child.wait_with_output().map_err(|e| {
        Error::Other(format!("FATAL: Failed to wait for signer process: {}", e))
    })?;

    // Check if the C program exited successfully
    if !output.status.success() {
        let err_msg = String::from_utf8_lossy(&output.stderr);
        error!("PQ Signer failed: {}", err_msg);
        return Err(Error::Other(format!(
            "FATAL: External PQ signer failed with error: {}",
            err_msg
        )));
    }

    let sig = output.stdout;

    if sig.is_empty() {
        return Err(Error::Other(
            "FATAL: PQ signature returned from external signer is empty".to_string()
        ));
    }

    debug!("PQ signature length: {} bytes", sig.len());
    Ok(sig)
}

 fn get_pq_signature_for_auth_tag_kernel(auth_tag_str: &str) -> Result<Vec<u8>> {
    const DEV_PATH: &str = "/dev/qubip_auth.tag";
    const SIG_PATH: &str = "/proc/qubip_auth.tag.sig";

    // 1) Write the quote to /dev/ (kernel signs it)
    let mut dev = OpenOptions::new()
        .write(true)
        .open(DEV_PATH)
        .map_err(|e| {
            Error::Other(format!(
                "FATAL: cannot open {} for PQ signing – kernel module missing or wrong permissions: {}",
                DEV_PATH, e
            ))
    })?;

    dev.write_all(auth_tag_str.as_bytes())
        .map_err(|e| {
            Error::Other(format!(
                "FATAL: Failed to write auth tag to {} - kernel module may be unloaded: {}",
                DEV_PATH, e
            ))
        })?;

    // 2) Read the resulting PQ signature from /proc/qubip_auth.tag.sig
    let sig = read(SIG_PATH).map_err(|e| {
        Error::Other(format!(
            "FATAL: Failed to read PQ signature from {} - module not functioning: {}",
            SIG_PATH, e
        ))
    })?;

    if sig.is_empty() {
        return Err(Error::Other(format!(
            "FATAL: PQ signature from {} is empty – invalid module response",
            SIG_PATH
        )));
    }

    debug!("PQ signature length: {} bytes", sig.len());
    Ok(sig)
}

fn read_in_file(path: String) -> std::io::Result<String> {
    let file = fs::File::open(path)?;
    let mut buf_reader = BufReader::new(file);
    let mut contents = String::new();
    let _ = buf_reader.read_to_string(&mut contents)?;
    Ok(contents)
}

#[cfg(feature = "testing")]
mod testing {
    use super::*;
    use crate::{config::KeylimeConfig, crypto::CryptoError};
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub(crate) enum MainTestError {
        /// Algorithm error
        #[error("AlgorithmError")]
        Error(#[from] keylime::algorithms::AlgorithmError),

        /// Crypto error
        #[error("CryptoError")]
        CryptoError(#[from] CryptoError),

        /// CryptoTest error
        #[error("CryptoTestError")]
        CryptoTestError(#[from] crypto::testing::CryptoTestError),

        /// IO error
        #[error("IOError")]
        IoError(#[from] std::io::Error),

        /// OpenSSL error
        #[error("IOError")]
        OpenSSLError(#[from] openssl::error::ErrorStack),

        /// TPM error
        #[error("TPMError")]
        TPMError(#[from] tpm::TpmError),

        /// TSS esapi error
        #[error("TSSError")]
        TSSError(#[from] tss_esapi::Error),
    }

    impl QuoteData {
        pub(crate) fn fixture() -> std::result::Result<Self, MainTestError> {
            let test_config = KeylimeConfig::default();
            let mut ctx = tpm::Context::new()?;

            let tpm_encryption_alg =
                keylime::algorithms::EncryptionAlgorithm::try_from(
                    test_config.agent.tpm_encryption_alg.as_str(),
                )?;

            // Gather EK and AK key values and certs
            let ek_result = ctx.create_ek(tpm_encryption_alg, None)?;

            let tpm_hash_alg = keylime::algorithms::HashAlgorithm::try_from(
                test_config.agent.tpm_hash_alg.as_str(),
            )?;

            let tpm_signing_alg =
                keylime::algorithms::SignAlgorithm::try_from(
                    test_config.agent.tpm_signing_alg.as_str(),
                )?;

            let ak_result = ctx.create_ak(
                ek_result.key_handle,
                tpm_hash_alg,
                tpm_signing_alg,
            )?;
            let ak_handle = ctx.load_ak(ek_result.key_handle, &ak_result)?;
            let ak_tpm2b_pub =
                PublicBuffer::try_from(ak_result.public)?.marshall()?;

            let rsa_key_path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("test-data")
                .join("test-rsa.pem");

            let (nk_pub, nk_priv) =
                crypto::testing::rsa_import_pair(rsa_key_path)?;

            let (mut payload_tx, mut payload_rx) =
                mpsc::channel::<payloads::PayloadMessage>(1);

            let (mut keys_tx, mut keys_rx) = mpsc::channel::<(
                keys_handler::KeyMessage,
                Option<oneshot::Sender<keys_handler::SymmKeyMessage>>,
            )>(1);

            let (mut revocation_tx, mut revocation_rx) =
                mpsc::channel::<revocation::RevocationMessage>(1);

            let revocation_cert =
                PathBuf::from(test_config.agent.revocation_cert);

            let actions_dir = Some(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/actions/"),
            );

            let work_dir =
                Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");

            let secure_mount = work_dir.join("tmpfs-dev");

            let ima_ml_path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("test-data/ima/ascii_runtime_measurements");
            let ima_ml_file = match fs::File::open(ima_ml_path) {
                Ok(file) => Some(Mutex::new(file)),
                Err(err) => None,
            };

            // Allow setting the binary bios measurements log path when testing
            let mut measuredboot_ml_path =
                Path::new(&test_config.agent.measuredboot_ml_path);
            let env_mb_path;
            #[cfg(feature = "testing")]
            if let Ok(v) = std::env::var("TPM_BINARY_MEASUREMENTS") {
                env_mb_path = v;
                measuredboot_ml_path = Path::new(&env_mb_path);
            }

            let measuredboot_ml_file =
                match fs::File::open(measuredboot_ml_path) {
                    Ok(file) => Some(Mutex::new(file)),
                    Err(err) => None,
                };

            Ok(QuoteData {
                tpmcontext: Mutex::new(ctx),
                priv_key: nk_priv,
                pub_key: nk_pub,
                ak_handle,
                keys_tx,
                payload_tx,
                revocation_tx,
                hash_alg: keylime::algorithms::HashAlgorithm::Sha256,
                enc_alg: keylime::algorithms::EncryptionAlgorithm::Rsa,
                sign_alg: keylime::algorithms::SignAlgorithm::RsaSsa,
                agent_uuid: test_config.agent.uuid,
                allow_payload_revocation_actions: test_config
                    .agent
                    .allow_payload_revocation_actions,
                secure_size: test_config.agent.secure_size,
                work_dir,
                ima_ml_file,
                measuredboot_ml_file,
                ima_ml: Mutex::new(MeasurementList::new()),
                secure_mount,
                pq_algorithm: "ml-dsa-87".to_string(), // default value for testing
                request_counter: AtomicUsize::new(0),
            })
        }
    }
}

// Unit Testing
#[cfg(test)]
mod tests {
    use super::*;

    fn init_logger() {
        pretty_env_logger::init();
        info!("Initialized logger for testing suite.");
    }

    #[test]
    fn test_read_in_file() {
        assert_eq!(
            read_in_file("test-data/test_input.txt".to_string())
                .expect("File doesn't exist"),
            String::from("Hello World!\n")
        );
    }
}