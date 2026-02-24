// // src/protection_modules/mitm_proxy.rs
// use std::sync::Arc;
// use tokio::net::TcpListener;
// use tokio::sync::{RwLock};
// use log::{info, warn};
// use crate::protection_modules::ca_manager::CaManager;
// use crate::policy_engine::PolicyEngine;
// use crate::communication::ServerCommunicator;
// use std::net::SocketAddr;
// use hyper::server::conn::Http;
// use hyper::{service::{service_fn}, Request, Response, Body, Client};
// use hyper::client::HttpConnector;
// use hyper::Method;
// use std::convert::Infallible;

// pub struct MitmProxy {
//     listen_addr: SocketAddr,
//     ca: Arc<CaManager>,
//     policy: Arc<RwLock<PolicyEngine>>,
//     communicator: Arc<ServerCommunicator>,
//     http_client: Client<HttpConnector>,
// }

// impl MitmProxy {
//     pub fn new(
//         listen: &str,
//         ca: Arc<CaManager>,
//         policy: Arc<RwLock<PolicyEngine>>,
//         communicator: Arc<ServerCommunicator>,
//     ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
//         let listen_addr: SocketAddr = listen.parse()?;
//         let http_client = Client::new();
//         Ok(Self {
//             listen_addr,
//             ca,
//             policy,
//             communicator,
//             http_client,
//         })
//     }

//     /// Start the proxy. This version handles plain HTTP by parsing requests via hyper.
//     /// TLS interception requires more rustls wiring (see earlier Phase 2), but here we
//     /// show how to integrate hyper request parsing with PolicyEngine hooks.
//     pub async fn run(&self) -> Result<(),  Box<dyn std::error::Error + Send + Sync>> {
//         let listener = TcpListener::bind(self.listen_addr).await?;
//         info!("MITM (HTTP) proxy listening on {}", self.listen_addr);

//         loop {
//             let (stream, addr) = listener.accept().await?;
//             let http_client = self.http_client.clone();
//             let policy = self.policy.clone();
//             let communicator = self.communicator.clone();
//             let ca = self.ca.clone();

//             tokio::spawn(async move {
//                 // Use hyper to serve per-connection: convert the TcpStream into a hyper server.
//                 let service = service_fn(|req: Request<Body>| {
//                     let http_client = http_client.clone();
//                     let policy = policy.clone();
//                     let communicator = communicator.clone();
//                     let ca = ca.clone();
//                     async move {
//                         // handle request and potentially block or forward
//                         handle_incoming_request(req, http_client, policy, communicator, ca).await
//                     }
//                 });

//                 if let Err(e) = Http::new().serve_connection(stream, service).await {
//                     warn!("Connection serve error: {}", e);
//                 }
//             });
//         }
//     }
// }

// /// Main per-request handler with policy hooks.
// async fn handle_incoming_request(
//     req: Request<Body>,
//     client: Client<HttpConnector>,
//     policy: Arc<RwLock<PolicyEngine>>,
//     communicator: Arc<ServerCommunicator>,
//     _ca: Arc<CaManager>
// ) -> Result<Response<Body>, Infallible> {
//     let uri = req.uri().clone();
//     let method = req.method().clone();
//     let headers = req.headers().clone();

//     // LOG / MONITOR
//     if policy.read().await.is_policy_active(crate::policy_constants::POLICY_WEB_MONITOR_HISTORY) {
//         // Record visited URL -> send later in batches (implement batching in communicator)
//         let url_str = uri.to_string();
//         // non-blocking alert / log:
//         let _ = communicator.queue_url_visit(&url_str).await; // implement queue in communicator
//     }

//     // UPLOAD detection: detect multipart/form-data or large POSTs
//     if (method == Method::POST || method == Method::PUT) &&
//        headers.get("content-type").map(|v| v.to_str().unwrap_or("").to_lowercase()).unwrap_or_default().contains("multipart/form-data")
//     {
//         // Check policy
//         if policy.read().await.is_policy_active(crate::policy_constants::POLICY_WEB_UPLOAD_BLOCK) {
//             // Send alert to server
//             let _ = communicator.send_web_alert("upload_blocked", &format!("Upload blocked to {}", uri)).await;
//             // Return 403 to client (soft block)
//             let mut res = Response::new(Body::from("Upload blocked by DLP policy."));
//             *res.status_mut() = hyper::StatusCode::FORBIDDEN;
//             return Ok(res);
//         }
//     }

//     // FORWARD REQUEST to target server
//     // Build a new request to upstream (absolute URI will be forwarded)
//     let forward_req = Request::builder()
//         .method(method.clone())
//         .uri(uri.clone())
//         .version(req.version());

//     // Copy headers (except hop-by-hop as needed)
//     let forward_req = forward_req.body(req.into_body()).unwrap();

//     // Make upstream request
//     match client.request(forward_req).await {
//         Ok(upstream_resp) => {
//             // Inspect response headers for downloads:
//             if policy.read().await.is_policy_active(crate::policy_constants::POLICY_WEB_DOWNLOAD_BLOCK) {
//                 if let Some(cd) = upstream_resp.headers().get("content-disposition") {
//                     if let Ok(cd_str) = cd.to_str() {
//                         // detect filename
//                         if cd_str.to_lowercase().contains("filename=") {
//                             // alert & block
//                             let _ = communicator.send_web_alert("download_blocked", &format!("Download blocked from {}: {}", uri, cd_str)).await;
//                             let mut res = Response::new(Body::from("Download blocked by DLP policy."));
//                             *res.status_mut() = hyper::StatusCode::FORBIDDEN;
//                             return Ok(res);
//                         }
//                     }
//                 }
//                 // or if content-type indicates executable or archive
//                 if let Some(ct) = upstream_resp.headers().get("content-type") {
//                     if let Ok(cts) = ct.to_str() {
//                         let ctlc = cts.to_lowercase();
//                         if ctlc.contains("application/x-msdownload") || ctlc.contains("application/zip") || ctlc.contains("application/octet-stream") {
//                             // optionally check filename or extension from uri
//                             let _ = communicator.send_web_alert("download_blocked", &format!("Blocked by content-type {} from {}", cts, uri)).await;
//                             let mut res = Response::new(Body::from("Download blocked by DLP policy."));
//                             *res.status_mut() = hyper::StatusCode::FORBIDDEN;
//                             return Ok(res);
//                         }
//                     }
//                 }
//             }

//             // If not blocked, forward response body to client unchanged
//             Ok(upstream_resp.map(|b| b).into_response())
//         }
//         Err(e) => {
//             warn!("Upstream request failed for {}: {}", uri, e);
//             let mut res = Response::new(Body::from("Upstream request failed"));
//             *res.status_mut() = hyper::StatusCode::BAD_GATEWAY;
//             Ok(res)
//         }
//     }
// }

// // helper for Response conversion (small convenience)
// trait IntoResponseBody {
//     fn into_response(self) -> Response<Body>;
// }
// impl IntoResponseBody for hyper::Response<Body> {
//     fn into_response(self) -> Response<Body> { self }
// }
