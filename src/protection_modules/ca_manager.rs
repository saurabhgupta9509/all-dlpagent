// // src/protection_modules/ca_manager.rs
// use rcgen::{Certificate, CertificateParams, IsCa, BasicConstraints, DistinguishedName};
// use std::path::{Path, PathBuf};
// use std::fs;
// use std::sync::Mutex;
// use std::collections::HashMap;
// use std::sync::Arc;

// pub struct CaManager {
//     ca_cert: Certificate,
//     ca_cert_pem: String,
//     ca_key_pem: String,
//     cache_dir: PathBuf,
//     // cache: hostname -> (cert_pem, key_pem)
//     cache: Mutex<HashMap<String, (String, String)>>,
// }

// impl CaManager {
//     pub fn new_or_load<P: AsRef<Path>>(persist_dir: P) -> Result<Arc<Self>,  Box<dyn std::error::Error + Send + Sync>> {
//         let persist_dir = persist_dir.as_ref().to_path_buf();
//         fs::create_dir_all(&persist_dir)?;
//         let cert_path = persist_dir.join("dlp_root_ca.crt");
//         let key_path = persist_dir.join("dlp_root_ca.key");

//         if cert_path.exists() && key_path.exists() {
//             // load existing
//             let cert_pem = fs::read_to_string(&cert_path)?;
//             let key_pem = fs::read_to_string(&key_path)?;
//             // rcgen cannot construct Certificate from PEM directly; regenerate from params is ideal,
//             // but for Phase 3 we'll keep CA in-memory only if we created it. If loading, we still
//             // keep bound PEMs for installation or export.
//             // For now: create a new self-signed CA (not ideal) — recommended: persist rcgen params in future.
//             let mut params = CertificateParams::new(vec![]);
//             params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
//             params.distinguished_name = DistinguishedName::new();
//             params.distinguished_name.push(rcgen::DnType::CommonName, "DLP Agent Root CA (reloaded)");
//             let ca = Certificate::from_params(params)?;
//             let ca_pem = cert_pem.clone();
//             let ca_key = key_pem.clone();
//             Ok(Arc::new(Self {
//                 ca_cert: ca,
//                 ca_cert_pem: ca_pem,
//                 ca_key_pem: ca_key,
//                 cache_dir: persist_dir,
//                 cache: Mutex::new(HashMap::new()),
//             }))
//         } else {
//             // generate new
//             let mut params = CertificateParams::new(vec![]);
//             params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
//             params.distinguished_name = DistinguishedName::new();
//             params.distinguished_name.push(rcgen::DnType::CommonName, "DLP Agent Root CA");
//             params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
//             let ca = Certificate::from_params(params)?;
//             let ca_pem = ca.serialize_pem()?;
//             let ca_key = ca.serialize_private_key_pem();

//             // persist PEMs
//             fs::write(&cert_path, &ca_pem)?;
//             fs::write(&key_path, &ca_key)?;

//             Ok(Arc::new(Self {
//                 ca_cert: ca,
//                 ca_cert_pem: ca_pem,
//                 ca_key_pem: ca_key,
//                 cache_dir: persist_dir,
//                 cache: Mutex::new(HashMap::new()),
//             }))
//         }
//     }

//     /// Return PEM of root certificate (exportable)
//     pub fn root_cert_pem(&self) -> &str {
//         &self.ca_cert_pem
//     }

//     /// Return PEM of private key (be careful!)
//     pub fn root_key_pem(&self) -> &str {
//         &self.ca_key_pem
//     }

//     /// Ensure on-disk cached leaf cert exists for hostname; returns (cert_pem, key_pem).
//     pub fn get_or_create_cert_for(&self, hostname: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
//         {
//             let c = self.cache.lock().unwrap();
//             if let Some(v) = c.get(hostname) {
//                 return Ok(v.clone());
//             }
//         }

//         // check on disk
//         let cert_file = self.cache_dir.join(format!("{}.crt", hostname));
//         let key_file = self.cache_dir.join(format!("{}.key", hostname));
//         if cert_file.exists() && key_file.exists() {
//             let cert_pem = fs::read_to_string(&cert_file)?;
//             let key_pem = fs::read_to_string(&key_file)?;
//             let mut c = self.cache.lock().unwrap();
//             c.insert(hostname.to_string(), (cert_pem.clone(), key_pem.clone()));
//             return Ok((cert_pem, key_pem));
//         }

//         // generate and sign with in-memory CA
//         let mut params = rcgen::CertificateParams::new(vec![hostname.to_string()]);
//         params.distinguished_name.push(rcgen::DnType::CommonName, hostname);
//         params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
//         let cert = rcgen::Certificate::from_params(params)?;
//         let cert_der = cert.serialize_der_with_signer(&self.ca_cert)?;
//         let cert_pem = pem::encode(&pem::Pem::new("CERTIFICATE".to_string(), cert_der));
//         let key_pem = cert.serialize_private_key_pem();

//         // persist
//         fs::write(&cert_file, &cert_pem)?;
//         fs::write(&key_file, &key_pem)?;

//         let mut c = self.cache.lock().unwrap();
//         c.insert(hostname.to_string(), (cert_pem.clone(), key_pem.clone()));

//         Ok((cert_pem, key_pem))
//     }

//     /// Admin helper: install root certificate into Windows Trusted Root (requires admin).
//     /// NOTE: run only after explicit admin consent.
//     pub fn install_root_cert_windows(&self) -> Result<(), Box<dyn std::error::Error>> {
//         let tmp_cert = self.cache_dir.join("dlp_root_ca.crt");
//         fs::write(&tmp_cert, &self.ca_cert_pem)?;
//         // certutil -addstore root dlp_root_ca.crt
//         let status = std::process::Command::new("certutil")
//             .args(["-addstore", "root", tmp_cert.to_str().unwrap()])
//             .status()?;
//         if !status.success() {
//             return Err("certutil failed (run as admin)".into());
//         }
//         Ok(())
//     }
// }
