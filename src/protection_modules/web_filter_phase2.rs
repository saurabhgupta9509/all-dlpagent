// // web_filter_phase2.rs
// // Phase 2: MITM Proxy listener for HTTPS inspection (minimal working foundation)
// //
// // Usage:
// //   let mut proxy = MitmProxy::new("127.0.0.1:8888").await?;
// //   proxy.run().await?;
// //
// // IMPORTANT: This is a foundation. Extend for production: persistent CA keys on disk,
// // certificate caching, robust error handling, connection pooling, performance tuning,
// // request parsing (multipart), throttling, and secure key storage.

// use std::fs;
// use std::path::Path;
// use std::sync::Arc;
// use std::net::{SocketAddr};
// use tokio::net::{TcpListener, TcpStream};
// use rustls::sign::CertifiedKey;
// use tokio_rustls::rustls::{ServerConfig, RootCertStore, OwnedTrustAnchor};
// use tokio_rustls::{TlsAcceptor, TlsConnector};
// use tokio::io::{AsyncReadExt, AsyncWriteExt};
// use tokio_rustls::rustls::ServerConfig as RustlsServerConfig;
// use rustls::server::ResolvesServerCert;
// use rustls::client::ClientConfig as RustlsClientConfig;
// use rustls::{Certificate, PrivateKey};
// use rcgen::{CertificateParams, BasicConstraints, IsCa, DistinguishedName, RcgenError};
// use webpki_roots::TLS_SERVER_ROOTS;
// use std::collections::HashMap;
// use std::sync::Mutex;
// use std::io::Write;
// use std::io::{self, ErrorKind};
// use log::{info, warn, debug};

// /// Simple in-memory CA manager: creates a self-signed Root CA (rcgen),
// /// can generate leaf certs for hostnames and return rustls CertifiedKey-like objects.
// struct CaManager {
//     ca_cert: rcgen::Certificate,
//     ca_privkey_der: Vec<u8>,
//     ca_cert_der: Vec<u8>,
//     // cache hostname -> (cert_der, privkey_der)
//     cache: Mutex<HashMap<String, (Vec<u8>, Vec<u8>)>>,
// }

// impl CaManager {

//     pub fn persist_root_ca(&self, cert_path: &str, key_path: &str) -> std::io::Result<()> {
//         fs::create_dir_all(Path::new(cert_path).parent().unwrap())?;

//         let mut cert_file = fs::File::create(cert_path)?;
//         cert_file.write_all(self.ca_cert_pem().as_bytes())?;

//         let mut key_file = fs::File::create(key_path)?;
//         key_file.write_all(self.ca_privkey_pem().as_bytes())?;

//         Ok(())
//     }

//     pub fn ca_cert_pem(&self) -> String {
//         self.ca_cert.serialize_pem().unwrap()
//     }

//     pub fn ca_privkey_pem(&self) -> String {
//         self.ca_cert.serialize_private_key_pem()
//     }
    
//     fn new_root_ca() -> Result<Self, RcgenError> {
//         let mut params = CertificateParams::new(vec![]);
//         params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
//         params.distinguished_name = DistinguishedName::new();
//         params.distinguished_name.push(rcgen::DnType::CommonName, "DLP Agent Root CA");
//         params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
//         let ca = rcgen::Certificate::from_params(params)?;

//         let ca_cert_der = ca.serialize_der()?;
//         let ca_privkey_der = ca.serialize_private_key_der();

//         Ok(Self {
//             ca_cert: ca,
//             ca_privkey_der,
//             ca_cert_der,
//             cache: Mutex::new(HashMap::new()),
//         })
//     }

//     /// Generate (or get cached) certificate for a given hostname
//     fn cert_for_hostname(&self, hostname: &str) -> Result<(Vec<u8>, Vec<u8>), RcgenError> {
//         {
//             let cache = self.cache.lock().unwrap();
//             if let Some(entry) = cache.get(hostname) {
//                 return Ok(entry.clone());
//             }
//         }

//         let mut params = CertificateParams::new(vec![hostname.to_string()]);
//         params.distinguished_name.push(rcgen::DnType::CommonName, hostname);
//         params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
//         let cert = rcgen::Certificate::from_params(params)?;
//         let cert_der = cert.serialize_der_with_signer(&self.ca_cert)?;
//         let privkey_der = cert.serialize_private_key_der();

//         let mut cache = self.cache.lock().unwrap();
//         cache.insert(hostname.to_string(), (cert_der.clone(), privkey_der.clone()));
//         Ok((cert_der, privkey_der))
//     }
// }

// /// Resolve certs for rustls ServerConfig using SNI
// struct DynamicResolver {
//     ca: Arc<CaManager>,
// }

// impl DynamicResolver {
//     fn new(ca: Arc<CaManager>) -> Self { Self { ca } }
// }

// impl ResolvesServerCert for DynamicResolver {
//     fn resolve(&self, client_hello: rustls::server::ClientHello) -> std::option::Option<Arc<CertifiedKey>> {
//         let sni = client_hello.server_name()?; // if no SNI, we can't do hostname-specific cert
//         match self.ca.cert_for_hostname(sni) {
//             Ok((cert_der, privkey_der)) => {
//                 let certs = vec![Certificate(cert_der)];
//                 let key = PrivateKey(privkey_der);
//                 let signing_key = rustls::sign::any_supported_type(&key).ok()?;
//                 Some(rustls::sign::CertifiedKey::new(certs, signing_key).into())
//             },
//             Err(e) => {
//                 warn!("Failed to create cert for {}: {:?}", sni, e);
//                 None
//             }
//         }
//     }
// }

// /// The MITM Proxy struct. Create, then call run().
// pub struct MitmProxy {
//     listen_addr: SocketAddr,
//     ca: Arc<CaManager>,
//     tls_client_config: Arc<RustlsClientConfig>,
//     // optional: you could persist CA files on disk and install them via certutil
// }

// impl MitmProxy {
//     /// Create new proxy, generate ephemeral Root CA (in memory)
//     pub async fn new(listen: &str) -> Result<Self, Box<dyn std::error::Error>> {
//         let listen_addr: SocketAddr = listen.parse()?;
//         let ca = Arc::new(CaManager::new_root_ca()?);

//         // Client config to connect to remote servers (trust system roots)
//         let mut root_store = RootCertStore::empty();
//         root_store.roots.extend(
//             TLS_SERVER_ROOTS.0.iter().map(|ta| {
//                 OwnedTrustAnchor::from_subject_spki_name_constraints(
//                     ta.subject, ta.spki, ta.name_constraints,
//                 )
//             })
//         );
        
        
//         let tls_client_config = RustlsClientConfig::builder()
//             .with_safe_defaults()
//             .with_root_certificates(root_store)
//             .with_no_client_auth();

//         Ok(Self {
//             listen_addr,
//             ca,
//             tls_client_config: Arc::new(tls_client_config),
//         })
//     }

//     /// Start listening and accept inbound proxy connections
//     pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
//         let listener = TcpListener::bind(&self.listen_addr).await?;
//         info!("🌐 MITM proxy listening on {}", self.listen_addr);

//         loop {
//             let (stream, addr) = listener.accept().await?;
//             let ca = self.ca.clone();
//             let client_tls_cfg = self.tls_client_config.clone();

//             tokio::spawn(async move {
//                 if let Err(e) = handle_client(stream, ca, client_tls_cfg).await {
//                     warn!("Connection handler failed for {}: {:?}", addr, e);
//                 }
//             });
//         }
//     }
// }

// /// Entry handler for each inbound connection.
// /// Reads the first request bytes to detect CONNECT vs plain HTTP.
// async fn handle_client(
//     inbound: TcpStream,
//     ca: Arc<CaManager>,
//     tls_client_cfg: Arc<RustlsClientConfig>,
// ) -> Result<(), Box<dyn std::error::Error>> {
//     // Peek into the stream to detect whether it's CONNECT (HTTPS) or plain HTTP
//     let mut buf = [0u8; 8192];
//     let n = inbound.peek(&mut buf).await?;
//     if n == 0 {
//         return Err("empty connection".into());
//     }
//     let header = String::from_utf8_lossy(&buf[..n]).to_string();
//     debug!("Initial client data: {}", header.lines().next().unwrap_or("..."));

//     if header.starts_with("CONNECT ") {
//         // Parse the CONNECT line: CONNECT host:port HTTP/1.1
//         if let Some(first_line) = header.lines().next() {
//             let parts: Vec<&str> = first_line.split_whitespace().collect();
//             if parts.len() >= 2 {
//                 let host_port = parts[1];
//                 return handle_connect_tunnel(inbound, host_port.to_string(), ca, tls_client_cfg).await;
//             }
//         }
//         return Err("Malformed CONNECT".into());
//     } else {
//         // Plain HTTP (not common for modern browsers when proxy set system-wide, but still handle)
//         return handle_plain_http(inbound, ca, tls_client_cfg).await;
//     }
// }

// /// Handle plain HTTP (non-encrypted) proxying — we can read the request, inspect, then forward.
// async fn handle_plain_http(
//     mut inbound: TcpStream,
//     _ca: Arc<CaManager>,
//     _tls_client_cfg: Arc<RustlsClientConfig>,
// ) -> Result<(), Box<dyn std::error::Error>> {
//     let mut buf = Vec::new();
//     let mut tmp = [0u8; 4096];
//     let n = inbound.read(&mut tmp).await?;
//     buf.extend_from_slice(&tmp[..n]);

//     let header = String::from_utf8_lossy(&buf).to_string();
//     let host = header
//         .lines()
//         .find_map(|l| if l.to_lowercase().starts_with("host:") { Some(l[5..].trim()) } else { None })
//         .ok_or("Host header missing")?;
//     let addr = if host.contains(':') { host.to_string() } else { format!("{}:80", host) };

//     let mut outbound = TcpStream::connect(addr).await?;
//     outbound.write_all(&buf).await?;

//     // proxy traffic both directions
//     tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;

//     Ok(())
// }


// /// Handle CONNECT method: create TLS with client using dynamic cert, connect to remote server, tunnel decrypted HTTP
// async fn handle_connect_tunnel(
//     mut inbound: TcpStream,
//     host_port: String,
//     ca: Arc<CaManager>,
//     tls_client_cfg: Arc<RustlsClientConfig>,
// ) -> Result<(), Box<dyn std::error::Error>> {
//     info!("Handling CONNECT for {}", host_port);

//     // 1) respond 200 OK to client to indicate tunnel established
//     inbound.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;

//     // 2) create a rustls ServerConfig with dynamic resolver for SNI
//     let server_cfg = RustlsServerConfig::builder()
//         .with_safe_defaults()
//         .with_no_client_auth();

//         let resolver = Arc::new(DynamicResolver::new(ca.clone()));
//         let server_cfg = ServerConfig::builder()
//         .with_safe_defaults()
//         .with_no_client_auth()
//         .with_cert_resolver(resolver);

//     let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

//     // 3) accept TLS from client — this yields decrypted client-side HTTP
//     let inbound_tls = acceptor.accept(inbound).await?;
//     // At this point, inbound_tls is a stream that yields plaintext HTTP from the client.

//     // 4) create a TLS connection to the real server (upstream)
//     // parse host and port
//     let mut hp_iter = host_port.split(':');
//     let host = hp_iter.next().unwrap_or("");
//     let port = hp_iter.next().unwrap_or("443");

//     // connect TCP to upstream
//     let outbound_tcp = TcpStream::connect(format!("{}:{}", host, port)).await?;
//     // create rustls client config connection with SNI host
//     let connector = TlsConnector::from(tls_client_cfg);
//     let domain = rustls::ServerName::try_from(host)
//         .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "invalid dnsname for sni"))?;
//     let outbound_tls = connector.connect(domain, outbound_tcp).await?;

//     // Now we have:
//     // - inbound_tls: decrypted stream from client (acting like a server)
//     // - outbound_tls: TLS stream to remote (acting like a client)
//     //
//     // We need to shuttle traffic between them, but also parse HTTP requests/responses
//     // so we can inspect uploads/downloads. For phase 2 foundation, we will forward bytes
//     // but also provide a simple hook that can parse headers for Content-Type / Content-Disposition
//     // in requests/responses so your policy engine can act.

//     // Two-way copy with lightweight inspection hooks
//     let (mut r_client, mut w_client) = tokio::io::split(inbound_tls);
//     let (mut r_server, mut w_server) = tokio::io::split(outbound_tls);

//     // spawn copy client -> server with inspection
//     let client_to_server = async {
//         let mut buf = [0u8; 16384];
//         loop {
//             let n = match r_client.read(&mut buf).await {
//                 Ok(0) => break,
//                 Ok(n) => n,
//                 Err(e) => {
//                     warn!("client read error: {}", e);
//                     break;
//                 }
//             };

//             // Simple inspection: try to parse headers from the chunk (best-effort)
//             if let Ok(head_str) = std::str::from_utf8(&buf[..n]) {
//                 if head_str.starts_with("POST") || head_str.starts_with("PUT") {
//                     // Inspect for multipart/form-data or file upload indicators
//                     inspect_upload_download("upload", head_str).await;
//                     // If policy engine says to block upload, we could close the connection or inject response.
//                     // TODO: call into the PolicyEngine via channel/handle to decide.
//                 }
//             }

//             if let Err(e) = w_server.write_all(&buf[..n]).await {
//                 warn!("error writing to server: {}", e);
//                 break;
//             }
//         }
//         // flush
//         let _ = w_server.shutdown().await;
//     };

//     // spawn copy server -> client with inspection
//     let server_to_client = async {
//         let mut buf = [0u8; 16384];
//         loop {
//             let n = match r_server.read(&mut buf).await {
//                 Ok(0) => break,
//                 Ok(n) => n,
//                 Err(e) => {
//                     warn!("server read error: {}", e);
//                     break;
//                 }
//             };

//             // Simple inspection for downloads based on response headers/file extensions
//             if let Ok(head_str) = std::str::from_utf8(&buf[..n]) {
//                 if head_str.starts_with("HTTP/") {
//                     inspect_upload_download("download", head_str).await;
//                     // TODO: if policy blocks, modify response to return 403 or silently drop
//                 }
//             }

//             if let Err(e) = w_client.write_all(&buf[..n]).await {
//                 warn!("error writing to client: {}", e);
//                 break;
//             }
//         }
//         let _ = w_client.shutdown().await;
//     };

//     tokio::select! {
//         _ = client_to_server => {},
//         _ = server_to_client => {},
//     }

//     Ok(())
// }

// /// Lightweight asynchronous hook to inspect request/response header text.
// /// In production, replace this with robust HTTP parsing and connection-level state tracking.
// /// You should call your PolicyEngine here (via channel, Arc<Mutex<..>>, or a global handle).
// async fn inspect_upload_download(direction: &str, header_text: &str) {
//     // Very naive heuristics: look for Content-Disposition filenames or common file extensions in a URL
//     if direction == "upload" {
//         if header_text.to_lowercase().contains("content-disposition:") {
//             info!("Upload attempt detected (basic heuristic).");
//             // TODO: send alert to admin dashboard and consult POLICY_WEB_UPLOAD_BLOCK.
//         }
//     } else if direction == "download" {
//         // inspect Content-Type or Content-Disposition
//         if header_text.to_lowercase().contains("content-disposition:") ||
//            header_text.to_lowercase().contains("content-type: application/octet-stream") ||
//            header_text.to_lowercase().contains("content-type: application/zip") ||
//            header_text.to_lowercase().contains("content-type: application/x-msdownload") {
//             info!("Download attempt detected (basic heuristic).");
//             // TODO: send alert and consult POLICY_WEB_DOWNLOAD_BLOCK
//         }
//     }
// }
