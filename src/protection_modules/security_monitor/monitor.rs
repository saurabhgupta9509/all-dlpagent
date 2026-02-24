// // Core real‑time monitoring loop: captures screenshots, runs OCR + NLP context analysis,
// // evaluates security rule violations, logs structured events, and triggers certificate generation.
// use crate::protection_modules::security_monitor::image_processing::{capture_screenshot, advanced_preprocess_image, document_preprocess_image};
// use crate::config::{OCR_INTERVAL, LOG_RETENTION};
// use crate::protection_modules::security_monitor::types::{LogEntry, Hit, Certificate, TextContext, ContextAnalysis};
// use crate::protection_modules::security_monitor::rule_engine::SecurityRuleEngine;
// use crate::protection_modules::security_monitor::ocr::OcrProcessor;
// use crate::protection_modules::security_monitor::llm_threat_assessor::LLMThreatAssessor;
// use crate::protection_modules::security_monitor::types;
// use image::DynamicImage;

// use std::collections::{HashMap, HashSet};
// use std::sync::Arc;
// use std::sync::atomic::{AtomicBool, Ordering};
// use std::time::{SystemTime, UNIX_EPOCH};
// use chrono::{DateTime, Utc};
// use std::fs;
// use std::path::Path;
// use std::io::Write;

// pub struct SecurityMonitor {
//     rule_engine: SecurityRuleEngine,
//     ocr_processor: OcrProcessor,
//     llm_assessor: LLMThreatAssessor,
//     violation_count: u32,
//     accumulated_logs: Vec<LogEntry>,
//     start_time: u64,
//     device_addr: String,
//     mac_addr: String,
//     last_certificate_time: u64,
//     context_history: Vec<TextContext>,
//     performance_metrics: PerformanceMetrics,

//      is_running: Arc<AtomicBool>,
// }

// #[derive(Debug, Clone)]
// struct PerformanceMetrics {
//     total_frames_processed: u64,
//     frames_with_text: u64,
//     average_processing_time: f64,
//     total_processing_time: f64,
//     last_processing_times: Vec<f64>,
// }

// impl PerformanceMetrics {
//     fn new() -> Self {
//         Self {
//             total_frames_processed: 0,
//             frames_with_text: 0,
//             average_processing_time: 0.0,
//             total_processing_time: 0.0,
//             last_processing_times: Vec::with_capacity(100),

//         }
//     }

//     fn record_processing_time(&mut self, duration: f64, had_text: bool) {
//         self.total_frames_processed += 1;
//         if had_text {
//             self.frames_with_text += 1;
//         }

//         self.total_processing_time += duration;
//         self.last_processing_times.push(duration);

//         // Keep only last 100 measurements
//         if self.last_processing_times.len() > 100 {
//             self.last_processing_times.remove(0);
//         }

//         // Update rolling average
//         self.average_processing_time = self.last_processing_times.iter().sum::<f64>() / self.last_processing_times.len() as f64;
//     }

//     fn get_text_detection_rate(&self) -> f64 {
//         if self.total_frames_processed == 0 {
//             return 0.0;
//         }
//         self.frames_with_text as f64 / self.total_frames_processed as f64 * 100.0
//     }
// }

// impl SecurityMonitor {
//     pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
//         let rule_engine = SecurityRuleEngine::new();
//         let ocr_processor = OcrProcessor::new()?;
//         let llm_assessor = LLMThreatAssessor::new();

//         let device_addr = get_device_addr();
//         let mac_addr = get_mac_addr();

//         Ok(Self {
//             rule_engine,
//             ocr_processor,
//             llm_assessor,
//             violation_count: 0,
//             accumulated_logs: Vec::new(),
//             start_time: current_timestamp(),
//             device_addr,
//             mac_addr,
//             last_certificate_time: current_timestamp(),
//             context_history: Vec::new(),
//             performance_metrics: PerformanceMetrics::new(),
//             is_running: Arc::new(AtomicBool::new(false)),
//         })
//     }

//     // Add this method to print the initialization banner
//     pub fn print_initialization_banner(&self) {
//         println!("🚀 Starting Advanced Security Monitor with NLP Enhancement...");
//         println!("💻 Device: {}", self.device_addr);
//         println!("🔗 MAC: {}", self.mac_addr);
//         println!("⏰ OCR Interval: 5s");
//         println!("📊 Certificate Generation: Every 60 seconds");
//         println!("🤖 LLM Threat Assessment: Enabled");
//         println!("🧠 NLP Context Awareness: Enabled");
//         println!("📈 Performance Monitoring: Active");
//         println!("🗑️ Cleanup: Screenshots (30s), Certificates (5m), Logs (10m)");
//         println!("🔧 Rule Engine: Enhanced with Context-Aware Validation");
//         println!("{}", "=".repeat(60));
//     }

//     // Add this method to check if maintenance should run
//     pub fn should_run_maintenance(&self) -> bool {
//         let current_time = current_timestamp();
//         current_time - self.last_certificate_time >= 60
//     }

//     pub async fn process_frame(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//         let start_time = std::time::Instant::now();

//         let img = capture_screenshot()?;
//         let timestamp = Utc::now();

//         // Save screenshot
//         let ss_path = self.save_screenshot(&img, &timestamp)?;

//         println!("🖥️ Captured screenshot: {}x{}", img.width(), img.height());

//         // Enhanced OCR with NLP
//         let ocr_result = self.try_ocr_with_preprocessing(&img);
//         let processing_time = start_time.elapsed().as_secs_f64();

//         let ocr_data = match ocr_result {
//             Ok(data) if !data.text.trim().is_empty() => {
//                 self.performance_metrics.record_processing_time(processing_time, true);
//                 data
//             }
//             Ok(_) => {
//                 self.performance_metrics.record_processing_time(processing_time, false);
//                 println!("⚠️ No text extracted from screenshot");
//                 return Ok(());
//             }
//             Err(e) => {
//                 self.performance_metrics.record_processing_time(processing_time, false);
//                 eprintln!("❌ OCR processing error: {}", e);
//                 return Ok(());
//             }
//         };

//         // Store context for pattern analysis
//         self.context_history.push(ocr_data.context.clone());
//         if self.context_history.len() > 10 {
//             self.context_history.remove(0);
//         }

//         println!("🔍 Enhanced OCR extracted {} characters", ocr_data.text.len());
//         println!("📊 NLP Analysis: {}", self.format_context_summary(&ocr_data.context));

//         if self.performance_metrics.total_frames_processed % 20 == 0 {
//             self.print_performance_stats();
//         }

//         // Check for violations with context awareness
//         let (full_violations, word_violations) =
//             self.rule_engine.check_ocr_data(&ocr_data.text, &ocr_data);

//         let all_violations: Vec<_> = full_violations.into_iter()
//             .chain(word_violations.into_iter())
//             .collect();

//         if !all_violations.is_empty() {
//             self.process_violations(&all_violations, &ss_path, &ocr_data.text, &timestamp, &ocr_data.context);
//         } else {
//             println!("✅ Scan clean - {} violations detected so far", self.violation_count);
//         }

//         Ok(())
//     }

//      pub fn print_banner(&self) {
//         println!("🚀 Starting Advanced Security Monitor with NLP Enhancement...");
//         println!("💻 Device: {}", self.device_addr);
//         println!("🔗 MAC: {}", self.mac_addr);
//         println!("⏰ OCR Interval: 5s");
//         println!("📊 Certificate Generation: Every 60 seconds");
//         println!("🤖 LLM Threat Assessment: Enabled");
//         println!("🧠 NLP Context Awareness: Enabled");
//         println!("📈 Performance Monitoring: Active");
//         println!("🗑️ Cleanup: Screenshots (30s), Certificates (5m), Logs (10m)");
//         println!("🔧 Rule Engine: Enhanced with Context-Aware Validation");
//         println!("{}", "=".repeat(60));
//     }

//     fn format_context_summary(&self, context: &TextContext) -> String {
//         format!(
//             "Lang: {}, Financial: {}, Business: {}, Tech: {}, Personal: {}, Readability: {:.1}",
//             context.language, context.is_financial, context.is_business,
//             context.is_technical, context.is_personal, context.readability_score
//         )
//     }

//     // Attempts multiple preprocessing strategies and selects the best OCR result based on a scoring heuristic.
//     fn try_ocr_with_preprocessing(&mut self, img: &DynamicImage) -> Result<crate::protection_modules::security_monitor::types::OcrData, Box<dyn std::error::Error>> {
//         // Define strategy type
//         type PreprocessStrategy = fn(&DynamicImage) -> DynamicImage;

//         // FIX: Use a vector instead of array for dynamic sizing
//         let strategies: Vec<(&str, PreprocessStrategy)> = vec![
//             ("document", document_preprocess_image),
//             ("advanced", advanced_preprocess_image),
//             ("original", |img: &DynamicImage| img.clone()),
//         ];

//         let mut best_result: Option<crate::protection_modules::security_monitor::types::OcrData> = None;
//         let mut best_score = 0;
//         let mut best_strategy = "none";

//         // FIX: Iterate over references to the vector
//         for (strategy_name, strategy) in &strategies {
//             let processed_img = strategy(img);
//             match self.ocr_processor.extract_text(&processed_img) {
//                 Ok(data) if !data.text.trim().is_empty() => {
//                     let score = self.calculate_ocr_quality(&data);
//                     if score > best_score {
//                         best_score = score;
//                         best_result = Some(data);
//                         best_strategy = strategy_name;
//                     }
//                 }
//                 Ok(_) => {
//                     continue;
//                 }
//                 Err(e) => {
//                     eprintln!("❌ OCR strategy '{}' failed: {}", strategy_name, e);
//                     continue;
//                 }
//             }
//         }

//         if let Some(result) = best_result {
//             println!("🎯 Best OCR strategy: {} (score: {})", best_strategy, best_score);
//             Ok(result)
//         } else {
//             Err("All OCR strategies failed to extract meaningful text".into())
//         }
//     }

//     // Computes heuristic OCR quality score combining text length, confidence, readability, and structure.
//     fn calculate_ocr_quality(&self, data: &crate::protection_modules::security_monitor::types::OcrData) -> usize {
//         let mut score = data.text.len();

//         // Bonus for good word confidence
//         if !data.words.is_empty() {
//             let avg_confidence: f32 = data.words.iter()
//                 .map(|w| w.confidence)
//                 .sum::<f32>() / data.words.len() as f32;

//             if avg_confidence > 0.7 {
//                 score += 100;
//             } else if avg_confidence > 0.5 {
//                 score += 50;
//             }
//         }

//         // Bonus for readable text (moderate complexity is best)
//         if data.context.readability_score > 30.0 && data.context.readability_score < 80.0 {
//             score += 50;
//         }

//         // Bonus for meaningful sentence structure
//         if data.context.sentence_count > 1 {
//             score += 30;
//         }

//         // Penalty for very short text
//         if data.text.len() < 20 {
//             score = score.saturating_sub(50);
//         }

//         score
//     }

//     // Normalizes violations into Hit records, logs them, prints contextual metadata, and updates counters.
//     async fn process_violations(
//         &mut self,
//         violations: &[types::Violation],
//         ss_path: &str,
//         text: &str,
//         timestamp: &DateTime<Utc>,
//         context: &TextContext,
//     ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//         self.violation_count += 1;

//         let mut rule_violations = HashMap::new();
//         let mut hits = Vec::new();

//         for violation in violations {
//             hits.push(Hit {
//                 rule: violation.rule_type.clone(),
//                 x: violation.x,
//                 y: violation.y,
//                 flagged_text: violation.matched_text.clone(),
//                 context_confidence: violation.context_confidence,
//                 contextual_evidence: violation.contextual_clues.clone(),
//             });

//             rule_violations
//                 .entry(violation.rule_type.clone())
//                 .or_insert_with(HashSet::new)
//                 .insert(violation.matched_text.clone());
//         }

//         let log_entry = LogEntry {
//             event: "violation".to_string(),
//             timestamp: timestamp.to_rfc3339(),
//             device: self.device_addr.clone(),
//             mac: self.mac_addr.clone(),
//             violation_count: self.violation_count,
//             rules_detected: rule_violations.len(),
//             screenshot: ss_path.to_string(),
//             hits: hits.clone(),
//             text_sample: if text.len() > 200 {
//                 format!("{}...", &text[..200])
//             } else {
//                 text.to_string()
//             },
//             rule_engine_used: true,
//             ocr_quality: self.assess_ocr_quality(text, context),
//             nlp_context: context.clone(),
//         };

//         self.write_log(&log_entry)?;
//         self.accumulated_logs.push(log_entry);

//         println!("🚨 CONTEXT-AWARE VIOLATION {}: {} unique rules detected",
//                  self.violation_count, rule_violations.len());

//         for (rule_type, texts) in &rule_violations {
//             println!("   📋 {} violations:", rule_type);
//             for text in texts {
//                 println!("      • '{}'", text);
//             }
//         }

//         // Print detailed context analysis
//         self.print_context_analysis(violations, context);

//         Ok(())
//     }

//     // Produces coarse OCR quality classification used in log summaries.
//     fn assess_ocr_quality(&self, text: &str, context: &TextContext) -> String {
//         if text.len() < 10 {
//             return "very_low".to_string();
//         }

//         let mut score = 0;

//         // Length-based scoring
//         if text.len() > 100 { score += 3; }
//         else if text.len() > 50 { score += 2; }
//         else if text.len() > 20 { score += 1; }

//         // Readability scoring
//         if context.readability_score > 50.0 && context.readability_score < 80.0 {
//             score += 2;
//         }

//         // Sentence structure scoring
//         if context.sentence_count > 2 {
//             score += 2;
//         }

//         match score {
//             5..=7 => "high".to_string(),
//             3..=4 => "medium".to_string(),
//             1..=2 => "low".to_string(),
//             _ => "very_low".to_string(),
//         }
//     }

//     // Outputs detailed NLP-derived context metadata and contextual clues for each violation.
//     fn print_context_analysis(&self, violations: &[types::Violation], context: &TextContext) {
//         println!("   📊 Context Analysis:");
//         println!("      Language: {}", context.language);
//         println!("      Financial Context: {}", context.is_financial);
//         println!("      Business Context: {}", context.is_business);
//         println!("      Technical Context: {}", context.is_technical);
//         println!("      Personal Context: {}", context.is_personal);
//         println!("      Contains Names: {}", context.contains_names);
//         println!("      Sentences: {}", context.sentence_count);
//         println!("      Avg Sentence Length: {:.1}", context.avg_sentence_length);
//         println!("      Readability Score: {:.1}", context.readability_score);

//         let mut high_confidence_violations = 0;
//         for violation in violations {
//             if violation.context_confidence > 0.8 {
//                 high_confidence_violations += 1;
//             }

//             if !violation.contextual_clues.is_empty() {
//                 println!("      🔍 Contextual Clues for {} (confidence: {:.2}):",
//                          violation.rule_type, violation.context_confidence);
//                 for clue in &violation.contextual_clues {
//                     println!("        • {}", clue);
//                 }
//             }
//         }

//         println!("      High Confidence Violations: {}/{}",
//                  high_confidence_violations, violations.len());
//     }

//     // Prints rolling OCR and frame-processing metrics collected over time.
//     fn print_performance_stats(&self) {
//         let metrics = &self.performance_metrics;
//         println!("📈 Performance Statistics:");
//         println!("   Total Frames: {}", metrics.total_frames_processed);
//         println!("   Text Detection Rate: {:.1}%", metrics.get_text_detection_rate());
//         println!("   Avg Processing Time: {:.2}s", metrics.average_processing_time);
//         println!("   Total Violations: {}", self.violation_count);
//         println!("   Context History Size: {}", self.context_history.len());
//     }

//     // Writes screenshot to structured time‑based folder hierarchy for retention + cleanup.
//     fn save_screenshot(&self, img: &image::DynamicImage, timestamp: &DateTime<Utc>) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
//         // Convert UTC to local time
//         let local_time = timestamp.with_timezone(&chrono::Local);

//         let date_folder = local_time.format("%Y-%m-%d").to_string();
//         let hour_folder = local_time.format("%H").to_string();
//         let base_dir = Path::new("screenshots").join(&date_folder).join(&hour_folder);

//         fs::create_dir_all(&base_dir)?;

//         let filename = format!("screenshot_{}.png", local_time.format("%Y%m%d_%H%M%S"));
//         let full_path = base_dir.join(&filename);

//         img.save_with_format(&full_path, image::ImageFormat::Png)?;

//         println!("📸 Screenshot saved: {}", full_path.display());
//         Ok(full_path.to_string_lossy().to_string())
//     }

//     // Appends a structured JSON log entry to an hourly rotating log file.
//     fn write_log(&self, entry: &LogEntry) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//         let logs_dir = Path::new("logs");
//         fs::create_dir_all(logs_dir)?;

//         let log_file = format!("logs/security_log_{}.json",
//                               Utc::now().format("%Y%m%d_%H"));

//         let log_line = serde_json::to_string(entry)? + "\n";

//         let mut file = fs::OpenOptions::new()
//             .create(true)
//             .append(true)
//             .open(log_file)?;

//         file.write_all(log_line.as_bytes())?;

//         Ok(())
//     }

//     // Periodic tasks: certificate generation, log shipping, and cleanup of old artifacts.
//     pub async fn maintenance_check(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//         let current_time = current_timestamp();

//         // Generate certificate every 60 seconds
//         if current_time - self.last_certificate_time >= 60 {
//             self.generate_and_save_certificate();
//             self.last_certificate_time = current_time;
//         }

//         // Send logs to server based on retention policy
//         if current_time - self.start_time >= LOG_RETENTION {
//             self.send_logs_to_server();
//             self.start_time = current_time;
//         }

//         // Cleanup operations
//         self.cleanup_old_screenshots()?;
//         self.cleanup_old_certificates()?;
//         self.cleanup_old_logs()?;

//         Ok(())
//     }

//     // Aggregates accumulated hits, performs threat assessment, prints and persists certificate.
//     async fn generate_and_save_certificate(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//         println!("📊 Generating enhanced threat assessment certificate...");

//         // Collect all hits from accumulated logs
//         let all_hits: Vec<Hit> = self.accumulated_logs.iter()
//             .flat_map(|log| log.hits.clone())
//             .collect();

//         // Collect context history for pattern analysis
//         let context_patterns = self.analyze_context_patterns();

//         // Generate certificate using enhanced assessor
//         let certificate = self.llm_assessor.generate_certificate(
//             &all_hits,
//             &self.device_addr,
//             &self.mac_addr,
//             &context_patterns,
//         ).await?;

//         // Print certificate
//         self.print_certificate(&certificate);

//         // Save certificate to file
//         self.save_certificate(&certificate)?;

//         Ok(())
//     }

//     // Aggregates NLP context samples to infer primary context and behavioral patterns.
//     fn analyze_context_patterns(&self) -> ContextAnalysis {
//         if self.context_history.is_empty() {
//             return ContextAnalysis {
//                 primary_context: "UNKNOWN".to_string(),
//                 risk_factors: vec!["No context data available".to_string()],
//                 behavioral_patterns: vec!["Initial monitoring phase".to_string()],
//                 confidence_score: 0.1,
//             };
//         }

//         // Analyze patterns in context history
//         let financial_count = self.context_history.iter().filter(|c| c.is_financial).count();
//         let business_count = self.context_history.iter().filter(|c| c.is_business).count();
//         let technical_count = self.context_history.iter().filter(|c| c.is_technical).count();
//         let personal_count = self.context_history.iter().filter(|c| c.is_personal).count();
//         let names_count = self.context_history.iter().filter(|c| c.contains_names).count();

//         let total = self.context_history.len();

//         let financial_ratio = financial_count as f32 / total as f32;
//         let business_ratio = business_count as f32 / total as f32;
//         let technical_ratio = technical_count as f32 / total as f32;
//         let personal_ratio = personal_count as f32 / total as f32;
//         let names_ratio = names_count as f32 / total as f32;

//         // Determine primary context
//         let primary_context = if financial_ratio > 0.4 {
//             "FINANCIAL"
//         } else if business_ratio > 0.4 {
//             "BUSINESS"
//         } else if technical_ratio > 0.4 {
//             "TECHNICAL"
//         } else if personal_ratio > 0.4 {
//             "PERSONAL"
//         } else {
//             "MIXED"
//         }.to_string();

//         let mut risk_factors = Vec::new();
//         if financial_ratio > 0.3 {
//             risk_factors.push(format!("Frequent financial content ({:.1}%)", financial_ratio * 100.0));
//         }
//         if names_ratio > 0.2 {
//             risk_factors.push(format!("Personal information present ({:.1}%)", names_ratio * 100.0));
//         }
//         if technical_ratio > 0.5 {
//             risk_factors.push("Heavy technical content".to_string());
//         }

//         let mut behavioral_patterns = Vec::new();
//         if total >= 5 {
//             behavioral_patterns.push("Established context patterns".to_string());
//         }

//         let avg_readability: f32 = self.context_history.iter()
//             .map(|c| c.readability_score)
//             .sum::<f32>() / total as f32;

//         if avg_readability < 30.0 {
//             behavioral_patterns.push("Simple text content".to_string());
//         } else if avg_readability > 70.0 {
//             behavioral_patterns.push("Complex text content".to_string());
//         }

//         // Calculate confidence based on data quality
//         let confidence_score = if total >= 3 {
//             0.7 + (total as f32 / 10.0).min(0.3)
//         } else {
//             0.5
//         };

//         ContextAnalysis {
//             primary_context,
//             risk_factors,
//             behavioral_patterns,
//             confidence_score: confidence_score.min(1.0),
//         }
//     }

//     // Sends accumulated logs after certificate generation; currently a placeholder for real transport.
//     async fn send_logs_to_server(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//         if self.accumulated_logs.is_empty() {
//             return Ok(());
//         }

//         println!("📤 SENDING {} LOGS TO SERVER", self.accumulated_logs.len());

//         // Generate final certificate before clearing logs
//         self.generate_and_save_certificate().await?;

//         // Here you would typically send logs to a remote server
//         // For now, we'll just clear them after certificate generation
//         println!("   📝 Logs would be sent to security server here");

//         self.accumulated_logs.clear();
//         Ok(())
//     }

//     // Persists generated certificate as a JSON file with timestamped filename.
//     fn save_certificate(&self, certificate: &Certificate) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//         let certs_dir = Path::new("certificates");
//         std::fs::create_dir_all(certs_dir)?;

//         let cert_file = format!("certificates/certificate_{}_{}.json",
//             certificate.user_device,
//             chrono::Utc::now().format("%Y%m%d_%H%M%S"));

//         let cert_json = serde_json::to_string_pretty(certificate)?;
//         std::fs::write(&cert_file, cert_json)?;

//         println!("💾 Certificate saved: {}", cert_file);
//         Ok(())
//     }

//     // Renders certificate in human‑readable form with threat scores, actions, and context breakdown.
//     fn print_certificate(&self, certificate: &Certificate) {
//         println!("\n{}", "=".repeat(70));
//         println!("🎯 ENHANCED THREAT ASSESSMENT CERTIFICATE GENERATED:");
//         println!("{}", "=".repeat(70));
//         println!("User: {} ({})", certificate.user_device, certificate.user_mac);
//         println!("Time: {}", certificate.assessment_time);
//         println!("Method: {}", certificate.assessment_method);
//         println!("LLM Available: {}", certificate.llm_available);
//         println!("Primary Context: {}", certificate.context_analysis.primary_context);
//         println!("Context Confidence: {:.1}%", certificate.context_analysis.confidence_score * 100.0);
//         println!("Threat Level: {} {}", certificate.emoji, certificate.threat_level);
//         println!("Score: {:.1}/100", certificate.threat_score);
//         println!("Total Violations: {}", certificate.total_violations);
//         println!("Unique Rule Types: {}", certificate.unique_rule_types);

//         if !certificate.context_analysis.risk_factors.is_empty() {
//             println!("\nRisk Factors:");
//             for factor in &certificate.context_analysis.risk_factors {
//                 println!("  • {}", factor);
//             }
//         }

//         println!("\nRisk Analysis: {}", certificate.risk_analysis);
//         println!("Behavior Insights: {}", certificate.behavior_insights);

//         println!("\nImmediate Actions:");
//         for action in &certificate.immediate_actions {
//             println!("  • {}", action);
//         }

//         println!("\nTraining Recommendations:");
//         for training in &certificate.training_recommendations {
//             println!("  • {}", training);
//         }

//         if !certificate.rule_breakdown.is_empty() {
//             println!("\nRule Violation Breakdown:");
//             for (rule, count) in &certificate.rule_breakdown {
//                 println!("  • {}: {}", rule, count);
//             }
//         }

//         println!("{}", "=".repeat(70));
//     }

//     // Removes expired artifacts based on age thresholds to maintain storage hygiene.
//     fn cleanup_old_screenshots(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//         let screenshots_dir = Path::new("screenshots");
//         if !screenshots_dir.exists() {
//             return Ok(());
//         }

//         let now = SystemTime::now();
//         let max_age = std::time::Duration::from_secs(30);

//         fn cleanup_directory(dir: &Path, now: SystemTime, max_age: std::time::Duration) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//             if dir.is_dir() {
//                 for entry in fs::read_dir(dir)? {
//                     let entry = entry?;
//                     let path = entry.path();

//                     if path.is_dir() {
//                         cleanup_directory(&path, now, max_age)?;
//                         if fs::read_dir(&path)?.next().is_none() {
//                             fs::remove_dir(&path)?;
//                             println!("🗑️ Deleted empty directory: {}", path.display());
//                         }
//                     } else if path.is_file() {
//                         if let Ok(metadata) = fs::metadata(&path) {
//                             if let Ok(modified) = metadata.modified() {
//                                 if now.duration_since(modified).unwrap_or(std::time::Duration::from_secs(0)) > max_age {
//                                     fs::remove_file(&path)?;
//                                     println!("🗑️ Deleted old screenshot: {}", path.display());
//                                 }
//                             }
//                         }
//                     }
//                 }
//             }
//             Ok(())
//         }

//         cleanup_directory(screenshots_dir, now, max_age)
//     }

//     // Removes expired artifacts based on age thresholds to maintain storage hygiene.
//     fn cleanup_old_certificates(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//         let certificates_dir = Path::new("certificates");
//         if !certificates_dir.exists() {
//             return Ok(());
//         }

//         let now = SystemTime::now();
//         let max_age = std::time::Duration::from_secs(300); // 5 minutes

//         if let Ok(entries) = fs::read_dir(certificates_dir) {
//             for entry in entries.flatten() {
//                 let path = entry.path();
//                 if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
//                     if let Ok(metadata) = fs::metadata(&path) {
//                         if let Ok(modified) = metadata.modified() {
//                             if now.duration_since(modified).unwrap_or(std::time::Duration::from_secs(0)) > max_age {
//                                 fs::remove_file(&path)?;
//                                 println!("🗑️ Deleted old certificate: {}", path.display());
//                             }
//                         }
//                     }
//                 }
//             }
//         }

//         Ok(())
//     }

//     // Removes expired artifacts based on age thresholds to maintain storage hygiene.
//     fn cleanup_old_logs(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//         let logs_dir = Path::new("logs");
//         if !logs_dir.exists() {
//             return Ok(());
//         }

//         let now = SystemTime::now();
//         let max_age = std::time::Duration::from_secs(600); // 10 minutes

//         if let Ok(entries) = fs::read_dir(logs_dir) {
//             for entry in entries.flatten() {
//                 let path = entry.path();
//                 if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
//                     if let Ok(metadata) = fs::metadata(&path) {
//                         if let Ok(modified) = metadata.modified() {
//                             if now.duration_since(modified).unwrap_or(std::time::Duration::from_secs(0)) > max_age {
//                                 fs::remove_file(&path)?;
//                                 println!("🗑️ Deleted old log: {}", path.display());
//                             }
//                         }
//                     }
//                 }
//             }
//         }

//         Ok(())
//     }

//     // Main runtime loop: cycles OCR → violation detection → maintenance, with periodic status output.
//     pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
//         println!("🚀 Starting Advanced Security Monitor with NLP Enhancement...");
//         println!("💻 Device: {}", self.device_addr);
//         println!("🔗 MAC: {}", self.mac_addr);
//         println!("⏰ OCR Interval: {}s", OCR_INTERVAL);
//         println!("📊 Certificate Generation: Every 60 seconds");
//         println!("🤖 LLM Threat Assessment: Enabled");
//         println!("🧠 NLP Context Awareness: Enabled");
//         println!("📈 Performance Monitoring: Active");
//         println!("🗑️ Cleanup: Screenshots (30s), Certificates (5m), Logs (10m)");
//         println!("🔧 Rule Engine: Enhanced with Context-Aware Validation");
//         println!("{}", "=".repeat(60));

//         let mut cycle_count = 0;

//         // Initial LLM availability check
//         self.llm_assessor.check_availability().await;

//         loop {
//             if let Err(e) = self.process_frame().await {
//                 eprintln!("❌ Frame processing error: {}", e);
//                 // Don't break on individual frame errors, continue monitoring
//             }

//             // Perform maintenance every 3 cycles (15 seconds with 5s interval)
//             if cycle_count % 3 == 0 {
//                 if let Err(e) = self.maintenance_check().await {
//                     eprintln!("❌ Maintenance error: {}", e);
//                 }
//             }

//             cycle_count += 1;

//             // Print status every 6 cycles (30 seconds)
//             if cycle_count % 6 == 0 {
//                 println!("\n📊 System Status:");
//                 println!("   Cycles Completed: {}", cycle_count);
//                 println!("   Total Violations: {}", self.violation_count);
//                 println!("   Active Logs: {}", self.accumulated_logs.len());
//                 println!("   Context History: {} samples", self.context_history.len());
//                 println!("   Text Detection Rate: {:.1}%", self.performance_metrics.get_text_detection_rate());
//                 println!("{}", "-".repeat(40));
//             }

//             tokio::time::sleep(tokio::time::Duration::from_secs(OCR_INTERVAL)).await;
//         }
//     }
// }

// fn get_device_addr() -> String {
//     // The local_ipaddress crate has a simpler API
//     local_ipaddress::get().unwrap_or_else(|| "0.0.0.0".to_string())
// }

// fn get_mac_addr() -> String {
//     match mac_address::get_mac_address() {
//         Ok(Some(addr)) => addr.to_string(),
//         Ok(None) => "00:00:00:00:00:00".to_string(),
//         Err(_) => "00:00:00:00:00:00".to_string(),
//     }
// }

// fn current_timestamp() -> u64 {
//     SystemTime::now()
//         .duration_since(UNIX_EPOCH)
//         .unwrap()
//         .as_secs()
// }

// src/protection_modules/security_monitor/monitor.rs

// use crate::protection_modules::security_monitor::types::{AgentStatus, CertificateSummary, MaintenanceLog, PerformanceUpdate, RealtimeUpdate, ScreenshotData, UpdateData, UpdateType, ViolationUpdate};

// use super::image_processing::{capture_screenshot, advanced_preprocess_image, document_preprocess_image};
// use super::types::{LogEntry, Hit, Certificate, TextContext, ContextAnalysis, OcrData, Violation};
// use super::rule_engine::SecurityRuleEngine;
// use super::ocr::OcrProcessor;
// use super::llm_threat_assessor::LLMThreatAssessor;
// use image::DynamicImage;

// use std::collections::{HashMap, HashSet};
// use std::sync::{Arc};
// use std::sync::mpsc;
// use std::sync::atomic::{AtomicBool, Ordering};
// use std::time::{SystemTime, UNIX_EPOCH};
// use chrono::{DateTime, Utc};
// use std::fs;
// use std::path::Path;
// use std::io::Write;
// use super::types::MonitorSettings;

// pub struct SecurityMonitor {
//     rule_engine: SecurityRuleEngine,
//     ocr_processor: OcrProcessor,
//     llm_assessor: LLMThreatAssessor,
//     violation_count: u32,
//     accumulated_logs: Vec<LogEntry>,
//     start_time: u64,
//     device_addr: String,
//     mac_addr: String,
//     last_certificate_time: u64,
//     context_history: Vec<TextContext>,
//     performance_metrics: PerformanceMetrics,
//     is_running: Arc<AtomicBool>,
//     realtime_tx: Option<mpsc::Sender<RealtimeUpdate>>, // NEW
//     last_screenshot_data: Option<ScreenshotData>,
// }

// #[derive(Debug, Clone)]
// struct PerformanceMetrics {
//     total_frames_processed: u64,
//     frames_with_text: u64,
//     average_processing_time: f64,
//     total_processing_time: f64,
//     last_processing_times: Vec<f64>,
// }

// impl PerformanceMetrics {
//     fn new() -> Self {
//         Self {
//             total_frames_processed: 0,
//             frames_with_text: 0,
//             average_processing_time: 0.0,
//             total_processing_time: 0.0,
//             last_processing_times: Vec::with_capacity(100),
//         }
//     }

//     fn record_processing_time(&mut self, duration: f64, had_text: bool) {
//         self.total_frames_processed += 1;
//         if had_text {
//             self.frames_with_text += 1;
//         }

//         self.total_processing_time += duration;
//         self.last_processing_times.push(duration);

//         // Keep only last 100 measurements
//         if self.last_processing_times.len() > 100 {
//             self.last_processing_times.remove(0);
//         }

//         // Update rolling average
//         self.average_processing_time = self.last_processing_times.iter().sum::<f64>() / self.last_processing_times.len() as f64;
//     }

//     fn get_text_detection_rate(&self) -> f64 {
//         if self.total_frames_processed == 0 {
//             return 0.0;
//         }
//         self.frames_with_text as f64 / self.total_frames_processed as f64 * 100.0
//     }
// }

// impl SecurityMonitor {
//     pub fn new(realtime_tx: mpsc::Sender<RealtimeUpdate>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
//         let rule_engine = SecurityRuleEngine::new();
//         // let ocr_processor = OcrProcessor::new()?;
//        let ocr_processor = OcrProcessor::new()?;
//             // .map_err(op);t::<Box<dyn std::error::Error + Send + Sync>, _>(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
//         let llm_assessor = LLMThreatAssessor::new();

//         let device_addr = Self::get_device_addr();
//         let mac_addr = Self::get_mac_addr();

//         Ok(Self {
//             rule_engine,
//             ocr_processor,
//             llm_assessor,
//             violation_count: 0,
//             accumulated_logs: Vec::new(),
//             start_time: Self::current_timestamp(),
//             device_addr,
//             mac_addr,
//             last_certificate_time: Self::current_timestamp(),
//             context_history: Vec::new(),
//             performance_metrics: PerformanceMetrics::new(),
//             is_running: Arc::new(AtomicBool::new(false)),
//             realtime_tx: Some(realtime_tx),
//             last_screenshot_data: None,
//         })
//     }

//     pub fn new_with_realtime(realtime_tx: mpsc::Sender<RealtimeUpdate>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
//         let rule_engine = SecurityRuleEngine::new();
//         // let ocr_processor = OcrProcessor::new()?;
//        let ocr_processor = OcrProcessor::new()?;
//             // .map_err(op);t::<Box<dyn std::error::Error + Send + Sync>, _>(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
//         let llm_assessor = LLMThreatAssessor::new();

//         let device_addr = Self::get_device_addr();
//         let mac_addr = Self::get_mac_addr();

//         Ok(Self {
//             rule_engine,
//             ocr_processor,
//             llm_assessor,
//             violation_count: 0,
//             accumulated_logs: Vec::new(),
//             start_time: Self::current_timestamp(),
//             device_addr,
//             mac_addr,
//             last_certificate_time: Self::current_timestamp(),
//             context_history: Vec::new(),
//             performance_metrics: PerformanceMetrics::new(),
//             is_running: Arc::new(AtomicBool::new(false)),
//             realtime_tx: Some(realtime_tx),
//             last_screenshot_data: None,
//         })
//     }

//     pub fn print_banner(&self) {
//         println!("🚀 Starting Advanced Security Monitor with NLP Enhancement...");
//         println!("💻 Device: {}", self.device_addr);
//         println!("🔗 MAC: {}", self.mac_addr);
//         println!("⏰ OCR Interval: 5s");
//         println!("📊 Certificate Generation: Every 60 seconds");
//         println!("🤖 LLM Threat Assessment: Enabled");
//         println!("🧠 NLP Context Awareness: Enabled");
//         println!("📈 Performance Monitoring: Active");
//         println!("🗑️ Cleanup: Screenshots (30s), Certificates (5m), Logs (10m)");
//         println!("🔧 Rule Engine: Enhanced with Context-Aware Validation");
//         println!("{}", "=".repeat(60));
//     }

//       pub fn should_run_maintenance(&self) -> bool {
//         let current_time = Self::current_timestamp();
//         current_time - self.last_certificate_time >= 60
//     }

//     pub async fn process_frame(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//         let start_time = std::time::Instant::now();

//         let img = capture_screenshot()?;
//         let timestamp = Utc::now();

//         // Save screenshot
//         let ss_path = self.save_screenshot(&img, &timestamp)?;
//          self.last_screenshot_data = Some(ScreenshotData {
//             path: ss_path.clone(),
//             dimensions: (img.width(), img.height()),
//             size_kb: (std::fs::metadata(&ss_path)?.len() as f32) / 1024.0,
//             preview_url: self.create_thumbnail_base64(&img)?,
//         });
//         println!("🖥️ Captured screenshot: {}x{}", img.width(), img.height());
//         // Create screenshot data for real-time

//         // Enhanced OCR with NLP
//         let ocr_result = match self.try_ocr_with_preprocessing(&img) {
//             Ok(r) => r,
//             Err(e) => {
//                 eprintln!("❌ OCR failed: {}", e);
//                 return Ok(());
//             }
//         };
//          // 4. Check violations
//         let (full_violations, word_violations) =
//             self.rule_engine.check_ocr_data(&ocr_result.text, &ocr_result);

//         let all_violations: Vec<_> = full_violations.into_iter()
//             .chain(word_violations.into_iter())
//             .collect();

//         // 5. Send violation updates in real-time
//         if !all_violations.is_empty() {
//             for violation in &all_violations {
//                 let violation_update = ViolationUpdate {
//                     id: format!("VIO_{}_{}", self.violation_count, chrono::Utc::now().timestamp_millis()),
//                     rule_type: violation.rule_type.clone(),
//                     matched_text: violation.matched_text.clone(),
//                     confidence: violation.confidence,
//                     context_confidence: violation.context_confidence,
//                     screenshot_path: ss_path.clone(),
//                     timestamp: timestamp.to_rfc3339(),
//                     contextual_clues: violation.contextual_clues.clone(),
//                 };

//                 // Send to real-time channel
//                 if let Some(tx) = &self.realtime_tx {
//                     let _ = tx.send(RealtimeUpdate {
//                         update_type: UpdateType::ViolationDetected,
//                         timestamp: chrono::Utc::now().to_rfc3339(),
//                         agent_id: 0, // Will be set by wrapper
//                         data: UpdateData::Violation(violation_update),
//                     });
//                 }
//             }

//             self.process_violations(&all_violations, &ss_path, &ocr_result.text, &timestamp, &ocr_result.context).await?;
//         }

//          // 6. Update performance metrics
//         let processing_time = start_time.elapsed().as_secs_f64();
//         self.performance_metrics.record_processing_time(processing_time, !ocr_result.text.trim().is_empty());

//         let ocr_data = match ocr_result {
//             Ok(data) if !data.text.trim().is_empty() => {
//                 self.performance_metrics.record_processing_time(processing_time, true);
//                 data
//             }
//             Ok(_) => {
//                 self.performance_metrics.record_processing_time(processing_time, false);
//                 println!("⚠️ No text extracted from screenshot");
//                 return Ok(());
//             }
//             Err(e) => {
//                 self.performance_metrics.record_processing_time(processing_time, false);
//                 eprintln!("❌ OCR processing error: {}", e);
//                 return Ok(());
//             }
//         };

//         // Store context for pattern analysis
//         self.context_history.push(ocr_data.context.clone());
//         if self.context_history.len() > 10 {
//             self.context_history.remove(0);
//         }

//         println!("🔍 Enhanced OCR extracted {} characters", ocr_data.text.len());
//         println!("📊 NLP Analysis: {}", self.format_context_summary(&ocr_data.context));

//         if self.performance_metrics.total_frames_processed % 20 == 0 {
//             self.print_performance_stats();
//         }

//         // Check for violations with context awareness
//         let (full_violations, word_violations) =
//             self.rule_engine.check_ocr_data(&ocr_data.text, &ocr_data);

//         let all_violations: Vec<_> = full_violations.into_iter()
//             .chain(word_violations.into_iter())
//             .collect();

//         if !all_violations.is_empty() {
//             self.process_violations(&all_violations, &ss_path, &ocr_data.text, &timestamp, &ocr_data.context).await?;
//         } else {
//             println!("✅ Scan clean - {} violations detected so far", self.violation_count);
//         }

//         Ok(())
//     }

//     pub async fn maintenance_check(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//         let cleaned_count = 0;
//         let space_freed = 0.0;
//         let current_time = Self::current_timestamp();

//         // Generate certificate every 60 seconds
//         if current_time - self.last_certificate_time >= 60 {
//             self.generate_and_save_certificate().await?;
//             self.last_certificate_time = current_time;
//         }

//         // Send logs to server based on retention policy
//         if current_time - self.start_time >= crate::config::LOG_RETENTION {
//             self.send_logs_to_server().await?;
//             self.start_time = current_time;
//         }

//             // Send certificate update
//         if let Some(certificate) = &self.last_certificate {
//             if let Some(tx) = &self.realtime_tx {
//                 let summary = CertificateSummary {
//                     certificate_id: certificate.certificate_id.clone(),
//                     generation_time: certificate.assessment_time.clone(),
//                     threat_score: certificate.threat_score,
//                     threat_level: certificate.threat_level.clone(),
//                     total_violations: certificate.total_violations,
//                     primary_context: certificate.context_analysis.primary_context.clone(),
//                     color_code: certificate.color_code.clone(),
//                     emoji: certificate.emoji.clone(),
//                     download_url: format!("certificates/{}", certificate.certificate_id),
//                 };

//                 let _ = tx.send(RealtimeUpdate {
//                     update_type: UpdateType::CertificateGenerated,
//                     timestamp: chrono::Utc::now().to_rfc3339(),
//                     agent_id: 0,
//                     data: UpdateData::Certificate(summary),
//                 });
//             }
//         }

//         // Send maintenance log
//         if let Some(tx) = &self.realtime_tx {
//             let _ = tx.send(RealtimeUpdate {
//                 update_type: UpdateType::MaintenanceCompleted,
//                 timestamp: chrono::Utc::now().to_rfc3339(),
//                 agent_id: 0,
//                 data: UpdateData::Maintenance(MaintenanceLog {
//                     action: "Scheduled cleanup".to_string(),
//                     details: format!("Cleaned {} old files", cleaned_count),
//                     files_cleaned: cleaned_count,
//                     space_freed_mb: space_freed,
//                 }),
//             });
//         }

//         // Cleanup operations
//         self.cleanup_old_screenshots()?;
//         self.cleanup_old_certificates()?;
//         self.cleanup_old_logs()?;

//         Ok(())
//     }
//      // Helper methods
//     pub fn get_last_screenshot_data(&self) -> Option<ScreenshotData> {
//         self.last_screenshot_data.clone()
//     }

//     fn get_current_settings(&self) -> MonitorSettings {
//         MonitorSettings {
//             ocr_interval: 5,
//             cleanup_screenshots_after: 30,
//             cleanup_certificates_after: 300,
//             cleanup_logs_after: 600,
//             llm_enabled: true,
//         }
//     }

//     pub fn get_status(&self) -> AgentStatus {
//         AgentStatus {
//             enabled: true,
//             last_activity: chrono::Utc::now().to_rfc3339(),
//             violations_today: self.violation_count,
//             screenshots_today: self.performance_metrics.total_frames_processed as u32,
//             certificates_today: self.certificates_generated_today,
//             current_settings: self.get_current_settings(),
//         }
//     }
//      pub fn get_performance_metrics(&self) -> PerformanceUpdate {
//         PerformanceUpdate {
//             frames_processed: self.performance_metrics.total_frames_processed,
//             text_detection_rate: self.performance_metrics.get_text_detection_rate(),
//             avg_processing_time: self.performance_metrics.average_processing_time,
//             cpu_usage: self.get_cpu_usage(),
//             memory_usage_mb: self.get_memory_usage(),
//             disk_usage_mb: self.get_disk_usage(),
//         }
//     }
//      fn create_thumbnail_base64(&self, img: &DynamicImage) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
//         // Create thumbnail (resize to 200x200)
//         let thumbnail = img.resize(200, 200, image::imageops::FilterType::Lanczos3);

//         // Convert to base64
//         let mut buffer = Vec::new();
//         thumbnail.write_to(&mut std::io::Cursor::new(&mut buffer), image::ImageFormat::Png)?;

//         Ok(Some(format!("data:image/png;base64,{}", base64::encode(buffer))))
//     }

//     // PRIVATE HELPER METHODS
//     fn format_context_summary(&self, context: &TextContext) -> String {
//         format!(
//             "Lang: {}, Financial: {}, Business: {}, Tech: {}, Personal: {}, Readability: {:.1}",
//             context.language, context.is_financial, context.is_business,
//             context.is_technical, context.is_personal, context.readability_score
//         )
//     }

//     fn try_ocr_with_preprocessing(&mut self, img: &DynamicImage) -> Result<OcrData, Box<dyn std::error::Error>> {
//         type PreprocessStrategy = fn(&DynamicImage) -> DynamicImage;

//         let strategies: Vec<(&str, PreprocessStrategy)> = vec![
//             ("document", document_preprocess_image),
//             ("advanced", advanced_preprocess_image),
//             ("original", |img: &DynamicImage| img.clone()),
//         ];

//         let mut best_result: Option<OcrData> = None;
//         let mut best_score = 0;
//         let mut best_strategy = "none";

//         for (strategy_name, strategy) in &strategies {
//             let processed_img = strategy(img);
//             match self.ocr_processor.extract_text(&processed_img) {
//                 Ok(data) if !data.text.trim().is_empty() => {
//                     let score = self.calculate_ocr_quality(&data);
//                     if score > best_score {
//                         best_score = score;
//                         best_result = Some(data);
//                         best_strategy = strategy_name;
//                     }
//                 }
//                 Ok(_) => continue,
//                 Err(e) => {
//                     eprintln!("❌ OCR strategy '{}' failed: {}", strategy_name, e);
//                     continue;
//                 }
//             }
//         }

//         if let Some(result) = best_result {
//             println!("🎯 Best OCR strategy: {} (score: {})", best_strategy, best_score);
//             Ok(result)
//         } else {
//             Err("All OCR strategies failed to extract meaningful text".into())
//         }
//     }

//     fn calculate_ocr_quality(&self, data: &OcrData) -> usize {
//         let mut score = data.text.len();

//         if !data.words.is_empty() {
//             let avg_confidence: f32 = data.words.iter()
//                 .map(|w| w.confidence)
//                 .sum::<f32>() / data.words.len() as f32;

//             if avg_confidence > 0.7 {
//                 score += 100;
//             } else if avg_confidence > 0.5 {
//                 score += 50;
//             }
//         }

//         if data.context.readability_score > 30.0 && data.context.readability_score < 80.0 {
//             score += 50;
//         }

//         if data.context.sentence_count > 1 {
//             score += 30;
//         }

//         if data.text.len() < 20 {
//             score = score.saturating_sub(50);
//         }

//         score
//     }

//     async fn process_violations(
//         &mut self,
//         violations: &[Violation],
//         ss_path: &str,
//         text: &str,
//         timestamp: &DateTime<Utc>,
//         context: &TextContext,
//     ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//         self.violation_count += 1;

//         let mut rule_violations = HashMap::new();
//         let mut hits = Vec::new();

//         for violation in violations {
//             hits.push(Hit {
//                 rule: violation.rule_type.clone(),
//                 x: violation.x,
//                 y: violation.y,
//                 flagged_text: violation.matched_text.clone(),
//                 context_confidence: violation.context_confidence,
//                 contextual_evidence: violation.contextual_clues.clone(),
//             });

//             rule_violations
//                 .entry(violation.rule_type.clone())
//                 .or_insert_with(HashSet::new)
//                 .insert(violation.matched_text.clone());
//         }

//         let log_entry = LogEntry {
//             event: "violation".to_string(),
//             timestamp: timestamp.to_rfc3339(),
//             device: self.device_addr.clone(),
//             mac: self.mac_addr.clone(),
//             violation_count: self.violation_count,
//             rules_detected: rule_violations.len(),
//             screenshot: ss_path.to_string(),
//             hits: hits.clone(),
//             text_sample: if text.len() > 200 {
//                 format!("{}...", &text[..200])
//             } else {
//                 text.to_string()
//             },
//             rule_engine_used: true,
//             ocr_quality: self.assess_ocr_quality(text, context),
//             nlp_context: context.clone(),
//         };

//         self.write_log(&log_entry)?;
//         self.accumulated_logs.push(log_entry);

//         println!("🚨 CONTEXT-AWARE VIOLATION {}: {} unique rules detected",
//                  self.violation_count, rule_violations.len());

//         for (rule_type, texts) in &rule_violations {
//             println!("   📋 {} violations:", rule_type);
//             for text in texts {
//                 println!("      • '{}'", text);
//             }
//         }

//         self.print_context_analysis(violations, context);

//         Ok(())
//     }

//     fn assess_ocr_quality(&self, text: &str, context: &TextContext) -> String {
//         if text.len() < 10 {
//             return "very_low".to_string();
//         }

//         let mut score = 0;

//         if text.len() > 100 { score += 3; }
//         else if text.len() > 50 { score += 2; }
//         else if text.len() > 20 { score += 1; }

//         if context.readability_score > 50.0 && context.readability_score < 80.0 {
//             score += 2;
//         }

//         if context.sentence_count > 2 {
//             score += 2;
//         }

//         match score {
//             5..=7 => "high".to_string(),
//             3..=4 => "medium".to_string(),
//             1..=2 => "low".to_string(),
//             _ => "very_low".to_string(),
//         }
//     }

//     fn print_context_analysis(&self, violations: &[Violation], context: &TextContext) {
//         println!("   📊 Context Analysis:");
//         println!("      Language: {}", context.language);
//         println!("      Financial Context: {}", context.is_financial);
//         println!("      Business Context: {}", context.is_business);
//         println!("      Technical Context: {}", context.is_technical);
//         println!("      Personal Context: {}", context.is_personal);
//         println!("      Contains Names: {}", context.contains_names);
//         println!("      Sentences: {}", context.sentence_count);
//         println!("      Avg Sentence Length: {:.1}", context.avg_sentence_length);
//         println!("      Readability Score: {:.1}", context.readability_score);

//         let mut high_confidence_violations = 0;
//         for violation in violations {
//             if violation.context_confidence > 0.8 {
//                 high_confidence_violations += 1;
//             }

//             if !violation.contextual_clues.is_empty() {
//                 println!("      🔍 Contextual Clues for {} (confidence: {:.2}):",
//                          violation.rule_type, violation.context_confidence);
//                 for clue in &violation.contextual_clues {
//                     println!("        • {}", clue);
//                 }
//             }
//         }

//         println!("      High Confidence Violations: {}/{}",
//                  high_confidence_violations, violations.len());
//     }

//     fn print_performance_stats(&self) {
//         let metrics = &self.performance_metrics;
//         println!("📈 Performance Statistics:");
//         println!("   Total Frames: {}", metrics.total_frames_processed);
//         println!("   Text Detection Rate: {:.1}%", metrics.get_text_detection_rate());
//         println!("   Avg Processing Time: {:.2}s", metrics.average_processing_time);
//         println!("   Total Violations: {}", self.violation_count);
//         println!("   Context History Size: {}", self.context_history.len());
//     }

//     fn save_screenshot(&self, img: &image::DynamicImage, timestamp: &DateTime<Utc>) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
//         let local_time = timestamp.with_timezone(&chrono::Local);

//         let date_folder = local_time.format("%Y-%m-%d").to_string();
//         let hour_folder = local_time.format("%H").to_string();
//         let base_dir = Path::new("screenshots").join(&date_folder).join(&hour_folder);

//         fs::create_dir_all(&base_dir)?;

//         let filename = format!("screenshot_{}.png", local_time.format("%Y%m%d_%H%M%S"));
//         let full_path = base_dir.join(&filename);

//         img.save_with_format(&full_path, image::ImageFormat::Png)?;

//         println!("📸 Screenshot saved: {}", full_path.display());
//         Ok(full_path.to_string_lossy().to_string())
//     }

//     fn write_log(&self, entry: &LogEntry) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//         let logs_dir = Path::new("logs");
//         fs::create_dir_all(logs_dir)?;

//         let log_file = format!("logs/security_log_{}.json",
//                               Utc::now().format("%Y%m%d_%H"));

//         let log_line = serde_json::to_string(entry)? + "\n";

//         let mut file = fs::OpenOptions::new()
//             .create(true)
//             .append(true)
//             .open(log_file)?;

//         file.write_all(log_line.as_bytes())?;

//         Ok(())
//     }

//     async fn generate_and_save_certificate(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//         println!("📊 Generating enhanced threat assessment certificate...");

//         let all_hits: Vec<Hit> = self.accumulated_logs.iter()
//             .flat_map(|log| log.hits.clone())
//             .collect();

//         let context_patterns = self.analyze_context_patterns();

//         let certificate = self.llm_assessor.generate_certificate(
//             &all_hits,
//             &self.device_addr,
//             &self.mac_addr,
//             &context_patterns,
//         ).await?;

//         self.print_certificate(&certificate);
//         self.save_certificate(&certificate)?;

//         Ok(())
//     }

//     fn analyze_context_patterns(&self) -> ContextAnalysis {
//         if self.context_history.is_empty() {
//             return ContextAnalysis {
//                 primary_context: "UNKNOWN".to_string(),
//                 risk_factors: vec!["No context data available".to_string()],
//                 behavioral_patterns: vec!["Initial monitoring phase".to_string()],
//                 confidence_score: 0.1,
//             };
//         }

//         let financial_count = self.context_history.iter().filter(|c| c.is_financial).count();
//         let business_count = self.context_history.iter().filter(|c| c.is_business).count();
//         let technical_count = self.context_history.iter().filter(|c| c.is_technical).count();
//         let personal_count = self.context_history.iter().filter(|c| c.is_personal).count();
//         let names_count = self.context_history.iter().filter(|c| c.contains_names).count();

//         let total = self.context_history.len();

//         let financial_ratio = financial_count as f32 / total as f32;
//         let business_ratio = business_count as f32 / total as f32;
//         let technical_ratio = technical_count as f32 / total as f32;
//         let personal_ratio = personal_count as f32 / total as f32;
//         let names_ratio = names_count as f32 / total as f32;

//         let primary_context = if financial_ratio > 0.4 {
//             "FINANCIAL"
//         } else if business_ratio > 0.4 {
//             "BUSINESS"
//         } else if technical_ratio > 0.4 {
//             "TECHNICAL"
//         } else if personal_ratio > 0.4 {
//             "PERSONAL"
//         } else {
//             "MIXED"
//         }.to_string();

//         let mut risk_factors = Vec::new();
//         if financial_ratio > 0.3 {
//             risk_factors.push(format!("Frequent financial content ({:.1}%)", financial_ratio * 100.0));
//         }
//         if names_ratio > 0.2 {
//             risk_factors.push(format!("Personal information present ({:.1}%)", names_ratio * 100.0));
//         }
//         if technical_ratio > 0.5 {
//             risk_factors.push("Heavy technical content".to_string());
//         }

//         let mut behavioral_patterns = Vec::new();
//         if total >= 5 {
//             behavioral_patterns.push("Established context patterns".to_string());
//         }

//         let avg_readability: f32 = self.context_history.iter()
//             .map(|c| c.readability_score)
//             .sum::<f32>() / total as f32;

//         if avg_readability < 30.0 {
//             behavioral_patterns.push("Simple text content".to_string());
//         } else if avg_readability > 70.0 {
//             behavioral_patterns.push("Complex text content".to_string());
//         }

//         let confidence_score = if total >= 3 {
//             0.7 + (total as f32 / 10.0).min(0.3)
//         } else {
//             0.5
//         };

//         ContextAnalysis {
//             primary_context,
//             risk_factors,
//             behavioral_patterns,
//             confidence_score: confidence_score.min(1.0),
//         }
//     }

//     async fn send_logs_to_server(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//         if self.accumulated_logs.is_empty() {
//             return Ok(());
//         }

//         println!("📤 SENDING {} LOGS TO SERVER", self.accumulated_logs.len());

//         self.generate_and_save_certificate().await?;
//         println!("   📝 Logs would be sent to security server here");

//         self.accumulated_logs.clear();
//         Ok(())
//     }

//     fn save_certificate(&self, certificate: &Certificate) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//         let certs_dir = Path::new("certificates");
//         std::fs::create_dir_all(certs_dir)?;

//         let cert_file = format!("certificates/certificate_{}_{}.json",
//             certificate.user_device,
//             chrono::Utc::now().format("%Y%m%d_%H%M%S"));

//         let cert_json = serde_json::to_string_pretty(certificate)?;
//         std::fs::write(&cert_file, cert_json)?;

//         println!("💾 Certificate saved: {}", cert_file);
//         Ok(())
//     }

//     fn print_certificate(&self, certificate: &Certificate) {
//         println!("\n{}", "=".repeat(70));
//         println!("🎯 ENHANCED THREAT ASSESSMENT CERTIFICATE GENERATED:");
//         println!("{}", "=".repeat(70));
//         println!("User: {} ({})", certificate.user_device, certificate.user_mac);
//         println!("Time: {}", certificate.assessment_time);
//         println!("Method: {}", certificate.assessment_method);
//         println!("LLM Available: {}", certificate.llm_available);
//         println!("Primary Context: {}", certificate.context_analysis.primary_context);
//         println!("Context Confidence: {:.1}%", certificate.context_analysis.confidence_score * 100.0);
//         println!("Threat Level: {} {}", certificate.emoji, certificate.threat_level);
//         println!("Score: {:.1}/100", certificate.threat_score);
//         println!("Total Violations: {}", certificate.total_violations);
//         println!("Unique Rule Types: {}", certificate.unique_rule_types);

//         if !certificate.context_analysis.risk_factors.is_empty() {
//             println!("\nRisk Factors:");
//             for factor in &certificate.context_analysis.risk_factors {
//                 println!("  • {}", factor);
//             }
//         }

//         println!("\nRisk Analysis: {}", certificate.risk_analysis);
//         println!("Behavior Insights: {}", certificate.behavior_insights);

//         println!("\nImmediate Actions:");
//         for action in &certificate.immediate_actions {
//             println!("  • {}", action);
//         }

//         println!("\nTraining Recommendations:");
//         for training in &certificate.training_recommendations {
//             println!("  • {}", training);
//         }

//         if !certificate.rule_breakdown.is_empty() {
//             println!("\nRule Violation Breakdown:");
//             for (rule, count) in &certificate.rule_breakdown {
//                 println!("  • {}: {}", rule, count);
//             }
//         }

//         println!("{}", "=".repeat(70));
//     }

//     fn cleanup_old_screenshots(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//         let screenshots_dir = Path::new("screenshots");
//         if !screenshots_dir.exists() {
//             return Ok(());
//         }

//         let now = SystemTime::now();
//         let max_age = std::time::Duration::from_secs(30);

//         fn cleanup_directory(dir: &Path, now: SystemTime, max_age: std::time::Duration) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//             if dir.is_dir() {
//                 for entry in fs::read_dir(dir)? {
//                     let entry = entry?;
//                     let path = entry.path();

//                     if path.is_dir() {
//                         cleanup_directory(&path, now, max_age)?;
//                         if fs::read_dir(&path)?.next().is_none() {
//                             fs::remove_dir(&path)?;
//                             println!("🗑️ Deleted empty directory: {}", path.display());
//                         }
//                     } else if path.is_file() {
//                         if let Ok(metadata) = fs::metadata(&path) {
//                             if let Ok(modified) = metadata.modified() {
//                                 if now.duration_since(modified).unwrap_or(std::time::Duration::from_secs(0)) > max_age {
//                                     fs::remove_file(&path)?;
//                                     println!("🗑️ Deleted old screenshot: {}", path.display());
//                                 }
//                             }
//                         }
//                     }
//                 }
//             }
//             Ok(())
//         }

//         cleanup_directory(screenshots_dir, now, max_age)
//     }

//     fn cleanup_old_certificates(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//         let certificates_dir = Path::new("certificates");
//         if !certificates_dir.exists() {
//             return Ok(());
//         }

//         let now = SystemTime::now();
//         let max_age = std::time::Duration::from_secs(300);

//         if let Ok(entries) = fs::read_dir(certificates_dir) {
//             for entry in entries.flatten() {
//                 let path = entry.path();
//                 if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
//                     if let Ok(metadata) = fs::metadata(&path) {
//                         if let Ok(modified) = metadata.modified() {
//                             if now.duration_since(modified).unwrap_or(std::time::Duration::from_secs(0)) > max_age {
//                                 fs::remove_file(&path)?;
//                                 println!("🗑️ Deleted old certificate: {}", path.display());
//                             }
//                         }
//                     }
//                 }
//             }
//         }

//         Ok(())
//     }

//     fn cleanup_old_logs(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//         let logs_dir = Path::new("logs");
//         if !logs_dir.exists() {
//             return Ok(());
//         }

//         let now = SystemTime::now();
//         let max_age = std::time::Duration::from_secs(600);

//         if let Ok(entries) = fs::read_dir(logs_dir) {
//             for entry in entries.flatten() {
//                 let path = entry.path();
//                 if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
//                     if let Ok(metadata) = fs::metadata(&path) {
//                         if let Ok(modified) = metadata.modified() {
//                             if now.duration_since(modified).unwrap_or(std::time::Duration::from_secs(0)) > max_age {
//                                 fs::remove_file(&path)?;
//                                 println!("🗑️ Deleted old log: {}", path.display());
//                             }
//                         }
//                     }
//                 }
//             }
//         }

//         Ok(())
//     }

//     // STATIC HELPER METHODS
//     fn get_device_addr() -> String {
//         local_ipaddress::get().unwrap_or_else(|| "0.0.0.0".to_string())
//     }

//     fn get_mac_addr() -> String {
//         match mac_address::get_mac_address() {
//             Ok(Some(addr)) => addr.to_string(),
//             Ok(None) => "00:00:00:00:00:00".to_string(),
//             Err(_) => "00:00:00:00:00:00".to_string(),
//         }
//     }

//     fn current_timestamp() -> u64 {
//         SystemTime::now()
//             .duration_since(UNIX_EPOCH)
//             .unwrap()
//             .as_secs()
//     }
// }

// src/protection_modules/security_monitor/monitor.rs
use crate::ServerCommunicator;
use crate::communication::{ OcrLiveData, OcrStatusUpdate, OcrViolation, SecurityCertificate };
use crate::config::LOG_RETENTION;
use crate::protection_modules::security_monitor::image_processing::{
    capture_screenshot,
    advanced_preprocess_image,
    document_preprocess_image,
};
use crate::protection_modules::security_monitor::llm_threat_assessor::LLMThreatAssessor;
use crate::protection_modules::security_monitor::ocr::OcrProcessor;
use crate::protection_modules::security_monitor::rule_engine::SecurityRuleEngine;
use crate::protection_modules::security_monitor::types::{
    AgentStatus,
    Certificate,
    CertificateSummary,
    ContextAnalysis,
    Hit,
    LogEntry,
    MaintenanceLog,
    MonitorSettings,
    OcrData,
    PerformanceUpdate,
    RealtimeUpdate,
    ScreenshotData,
    TextContext,
    UpdateData,
    UpdateType,
    Violation,
    ViolationUpdate,
};

use base64::{ engine::general_purpose, Engine as _ };
use chrono::{ DateTime, Utc };
use image::DynamicImage;
use local_ipaddress;
use mac_address;
use tokio::sync::{ Mutex, RwLock };

use std::collections::{ HashMap, HashSet };
use std::fs;
use std::io::Write;
use std::path::{ Path, PathBuf };
use std::sync::atomic::{ AtomicBool, Ordering };
use std::sync::{ Arc, mpsc };
use std::time::{ Duration, SystemTime, UNIX_EPOCH };
use sysinfo::{ System, Disks };

#[derive(Debug, Clone)]
struct PerformanceMetrics {
    total_frames_processed: u64,
    frames_with_text: u64,
    average_processing_time: f64,
    total_processing_time: f64,
    last_processing_times: Vec<f64>,
}

impl PerformanceMetrics {
    fn new() -> Self {
        Self {
            total_frames_processed: 0,
            frames_with_text: 0,
            average_processing_time: 0.0,
            total_processing_time: 0.0,
            last_processing_times: Vec::with_capacity(100),
        }
    }

    fn record_processing_time(&mut self, duration: f64, had_text: bool) {
        self.total_frames_processed += 1;
        if had_text {
            self.frames_with_text += 1;
        }

        self.total_processing_time += duration;
        self.last_processing_times.push(duration);

        if self.last_processing_times.len() > 100 {
            self.last_processing_times.remove(0);
        }

        if !self.last_processing_times.is_empty() {
            self.average_processing_time =
                self.last_processing_times.iter().sum::<f64>() /
                (self.last_processing_times.len() as f64);
        }
    }

    fn get_text_detection_rate(&self) -> f64 {
        if self.total_frames_processed == 0 {
            return 0.0;
        }
        ((self.frames_with_text as f64) / (self.total_frames_processed as f64)) * 100.0
    }
}

// ✅ NEW: Violation record for tracking
#[derive(Debug, Clone)]
struct ViolationRecord {
    rule_type: String,
    confidence: f32,
    context_confidence: f32,
    timestamp: u64,
}

// ✅ NEW: Trend enum
#[derive(Debug, Clone, PartialEq)]
pub enum ScoreTrend {
    Up, // Badh raha hai (red)
    Down, // Kam ho raha hai (green)
    Stable, // Same hai (neutral)
}

// ✅ NEW: Helper function to get rule weights
fn get_rule_weight_map() -> HashMap<String, f32> {
    let mut weights = HashMap::new();
    weights.insert("credit_card".to_string(), 85.0);
    weights.insert("ssn".to_string(), 80.0);
    weights.insert("aadhaar_card".to_string(), 80.0);
    weights.insert("pan_card".to_string(), 70.0);
    weights.insert("email_sensitive".to_string(), 60.0); // ✅ Increased email weight
    weights.insert("phone_number".to_string(), 60.0);
    weights.insert("password".to_string(), 80.0);
    weights
}

// ✅ Helper function to get rule weight
fn get_rule_weight(rule_type: &str) -> f32 {
    match rule_type {
        "credit_card" => 8.0,
        "ssn" => 7.0,
        "aadhaar_card" => 7.0,
        "pan_card" => 6.0,
        "email_sensitive" => 8.0,
        _ => 5.0,
    }
}
pub struct SecurityMonitor {
    // pub token: String,
    pub last_violation_ids: Vec<u64>,
    pub token: Arc<Mutex<String>>,
    pub agent_id: u64,
    pub rule_engine: SecurityRuleEngine,
    pub ocr_processor: OcrProcessor,
    pub llm_assessor: LLMThreatAssessor,

    pub violation_count: u32,
    pub accumulated_logs: Vec<LogEntry>,

    pub start_time: u64,
    pub device_addr: String,
    pub mac_addr: String,
    pub last_certificate_time: u64,

    pub context_history: Vec<TextContext>,
    pub performance_metrics: PerformanceMetrics,
    pub is_running: Arc<AtomicBool>,

    pub realtime_tx: Option<mpsc::Sender<RealtimeUpdate>>,
    pub last_screenshot_data: Option<ScreenshotData>,

    pub last_certificate: Option<Certificate>,
    pub certificates_generated_today: u32,

    pub screenshots_base_dir: PathBuf,
    pub logs_dir: PathBuf,
    pub certificates_dir: PathBuf,
    pub communicator: Arc<RwLock<ServerCommunicator>>,

    // ✅ NEW: 24-hour threat tracking
    pub violation_history_24h: Vec<(ViolationRecord, u64)>, // (violation, timestamp)
    pub previous_threat_score: f32, // Previous hour's score for trend
    pub current_threat_score: f32, // Current calculated score

    // ✅ NEW: Score display metadata
    pub last_update_time: u64,
    pub score_trend: ScoreTrend, // UP/DOWN/STABLE
    pub last_screenshot_time: Option<DateTime<Utc>>,
}

impl SecurityMonitor {
    // Add rate limiting for violations
    async fn send_violations_with_rate_limit(
        &mut self,
        violations: &[Violation],
        ss_path: &str,
        screenshot_timestamp: &DateTime<Utc>,  // For screenshot reference
        detection_timestamp: &DateTime<Utc>,   
        communicator: &ServerCommunicator,
        token: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Rate limit: Send max 5 violations per second
        const MAX_PER_SECOND: usize = 5;
        const DELAY_MS: u64 = 200; // 200ms between batches

        for chunk in violations.chunks(MAX_PER_SECOND) {
            // Collect violation IDs in a vector
            let mut violation_ids = Vec::new();

            for violation in chunk {
                match
                    self.send_ocr_violation(
                        violation,
                        ss_path,
                         screenshot_timestamp,
                    detection_timestamp,
                        communicator,
                        token
                    ).await
                {
                    Ok(id) => violation_ids.push(id),
                    Err(e) => log::error!("Failed to send violation: {}", e),
                }
            }

            // Store collected IDs
            self.last_violation_ids.extend(violation_ids);

            // Delay between chunks
            if chunk.len() == MAX_PER_SECOND {
                tokio::time::sleep(Duration::from_millis(DELAY_MS)).await;
            }
        }

        Ok(())
    }

    pub async fn update_token(&self, new_token: String) {
        log::info!("🔑 SecurityMonitor token updated.");
        let mut t = self.token.lock().await;
        *t = new_token;
    }

    pub fn new(
        agent_id: u64,
        token: String,
        realtime_tx: mpsc::Sender<RealtimeUpdate>,
        communicator: Arc<RwLock<ServerCommunicator>>
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let token_shared = Arc::new(Mutex::new(token));
        let rule_engine = SecurityRuleEngine::new();
        let ocr_processor = OcrProcessor::new()?;
        let llm_assessor = LLMThreatAssessor::new();

        let device_addr = Self::get_device_addr();
        let mac_addr = Self::get_mac_addr();

        let base_dir = PathBuf::from("security_monitor");
        let screenshots_base_dir = base_dir.join("screenshots");
        let logs_dir = base_dir.join("logs");
        let certificates_dir = base_dir.join("certificates");

        fs::create_dir_all(&screenshots_base_dir)?;
        fs::create_dir_all(&logs_dir)?;
        fs::create_dir_all(&certificates_dir)?;

        Ok(Self {
            last_violation_ids: Vec::new(),
            token: token_shared,
            agent_id,
            rule_engine,
            ocr_processor,
            llm_assessor,
            violation_count: 0,
            accumulated_logs: Vec::new(),
            start_time: Self::current_timestamp(),
            device_addr,
            mac_addr,
            last_certificate_time: Self::current_timestamp(),
            context_history: Vec::new(),
            performance_metrics: PerformanceMetrics::new(),
            is_running: Arc::new(AtomicBool::new(false)),
            realtime_tx: Some(realtime_tx),
            last_screenshot_data: None,
            last_certificate: None,
            certificates_generated_today: 0,
            screenshots_base_dir,
            logs_dir,
            certificates_dir,
            communicator,
            // Initialize new fields
            violation_history_24h: Vec::new(),
            previous_threat_score: 0.0,
            current_threat_score: 0.0,
            last_update_time: Self::current_timestamp(),
            score_trend: ScoreTrend::Stable,
            last_screenshot_time: None,
        })
    }

    // ✅ FIXED: This method should NOT be mutable - create a separate method for updating
    pub fn calculate_current_threat_score(&self) -> f32 {
        self.current_threat_score
    }

    // ✅ NEW: Update threat score with new violations
    pub fn update_threat_score_with_violations(&mut self, violations: &[Violation]) -> f32 {
        let now = Self::current_timestamp();

        // Add new violations to history
        for violation in violations {
            let record = ViolationRecord {
                rule_type: violation.rule_type.clone(),
                confidence: violation.confidence,
                context_confidence: violation.context_confidence,
                timestamp: now,
            };
            self.violation_history_24h.push((record, now));
        }

        // Keep only last 1000 records (performance)
        if self.violation_history_24h.len() > 1000 {
            self.violation_history_24h.drain(0..self.violation_history_24h.len() - 1000);
        }

        // Calculate new score
        self.recalculate_threat_score(now)
    }

    // ✅ NEW: Recalculate threat score (private helper)
    // fn recalculate_threat_score(&mut self, now: u64) -> f32 {
    //     let twenty_four_hours_ago = now.saturating_sub(24 * 60 * 60);

    //     // Step 1: Filter violations from last 24 hours
    //     let recent_violations: Vec<&ViolationRecord> = self.violation_history_24h
    //         .iter()
    //         .filter(|(_, timestamp)| *timestamp >= twenty_four_hours_ago)
    //         .map(|(record, _)| record)
    //         .collect();

    //     if recent_violations.is_empty() {
    //         // No violations in last 24 hours - apply decay
    //         let hours_since_last_violation = if !self.violation_history_24h.is_empty() {
    //             let (_, last_timestamp) = self.violation_history_24h.last().unwrap();
    //             let hours_passed = (now - last_timestamp) / 3600;
    //             hours_passed as f32
    //         } else {
    //             0.0
    //         };

    //         // Apply decay: reduce 10% for every hour after 24 hours
    //         let decay_factor = (1.0 - hours_since_last_violation * 0.1).max(0.1);
    //         self.current_threat_score = self.current_threat_score * decay_factor;
    //     } else {
    //         // Step 2: Calculate weighted average for recent violations
    //         let weights = get_rule_weight_map();

    //         let weighted_sum: f32 = recent_violations
    //             .iter()
    //             .map(|record| {
    //                 let weight = weights.get(&record.rule_type).unwrap_or(&5.0);
    //                 weight * record.context_confidence * 12.5 // Scale to 0-100
    //             })
    //             .sum();
                
    //         let avg_score = if !recent_violations.is_empty() {
    //             weighted_sum / recent_violations.len() as f32
    //         } else {
    //             0.0
    //         };    
    //         // let avg_score = weighted_sum / recent_violations.len() as f32;
    //         let count_multiplier = match recent_violations.len() {
    //             0 => 1.0,
    //             1 => 1.0,
    //             2..=3 => 1.1,  // 10% increase
    //             4..=6 => 1.2,  // 20% increase
    //             7..=10 => 1.3, // 30% increase
    //             _ => 1.4,      // 40% increase maximum
    //         };
    //         let weighted_score = avg_score * count_multiplier;

    //         // Step 3: Apply time decay for older violations
    //         let time_weighted_score = self.apply_time_decay(
    //             &recent_violations,
    //             now,
    //             twenty_four_hours_ago
    //         );

    //         // Step 4: Final score (avg + time weighted)
    //         self.current_threat_score = (weighted_score * 0.7 + time_weighted_score * 0.3).min(100.0);
    //     }

    //     // Step 5: Calculate trend
    //     self.update_trend();

    //     // Step 6: Never return 0 if we have any history
    //     if self.current_threat_score < 1.0 && !self.violation_history_24h.is_empty() {
    //         self.current_threat_score = 10.0; // Minimum display score
    //     }

    //     self.current_threat_score
    // }

    fn recalculate_threat_score(&mut self, now: u64) -> f32 {
    let twenty_four_hours_ago = now.saturating_sub(24 * 60 * 60);

    // Filter violations from last 24 hours
    let recent_violations: Vec<&ViolationRecord> = self.violation_history_24h
        .iter()
        .filter(|(_, timestamp)| *timestamp >= twenty_four_hours_ago)
        .map(|(record, _)| record)
        .collect();

    if recent_violations.is_empty() {
        // Apply decay when no recent violations
        let hours_since_last_violation = if !self.violation_history_24h.is_empty() {
            let (_, last_timestamp) = self.violation_history_24h.last().unwrap();
            let hours_passed = (now - last_timestamp) / 3600;
            hours_passed as f32
        } else {
            0.0
        };

        // Decay 10% for every hour after 24 hours
        let decay_factor = (1.0 - hours_since_last_violation * 0.1).max(0.1);
        self.current_threat_score = self.current_threat_score * decay_factor;
    } else {
        // Get rule weights
        let weights = get_rule_weight_map();
        
        // Count violations by rule type
        let mut rule_counts: HashMap<String, usize> = HashMap::new();
        let mut total_weighted_sum = 0.0;
        
        for record in &recent_violations {
            *rule_counts.entry(record.rule_type.clone()).or_insert(0) += 1;
        }
        
        // Calculate weighted sum: (count * weight) for each rule type
        for (rule_type, count) in rule_counts {
            if let Some(weight) = weights.get(&rule_type) {
                total_weighted_sum += (count as f32) * weight;
            } else {
                total_weighted_sum += (count as f32) * 5.0; // Default weight
            }
        }
        
        // Calculate average: total_weighted_sum / total_violations
        let total_violations = recent_violations.len() as f32;
        let avg_score = if total_violations > 0.0 {
            total_weighted_sum / total_violations
        } else {
            0.0
        };

        // Apply time decay for older violations
        let time_weighted_score = self.apply_time_decay(
            &recent_violations,
            now,
            twenty_four_hours_ago
        );

        // Final score: 70% weighted + 30% time-decayed
        self.current_threat_score = (avg_score * 0.7 + time_weighted_score * 0.3).min(100.0);
    }

    // Update trend and ensure minimum display score
    self.update_trend();

    // Never return 0 if we have any history
    if self.current_threat_score < 1.0 && !self.violation_history_24h.is_empty() {
        self.current_threat_score = 5.0; // Minimum display score
    }

    self.current_threat_score
}

    // ✅ NEW: Time decay function
    fn apply_time_decay(&self, violations: &[&ViolationRecord], now: u64, cutoff: u64) -> f32 {
        let mut weighted_sum = 0.0;
        let mut total_weight = 0.0;

        for record in violations {
            let age_seconds = now.saturating_sub(record.timestamp);
            let age_hours = (age_seconds as f32) / 3600.0;

            // Weight decays over time: recent = 1.0, 24 hours old = 0.1
            let time_weight = 1.0 - ((age_hours / 24.0) * 0.9).max(0.0).min(0.9);

            // Get rule weight directly without creating the full map
            let rule_weight = get_rule_weight(&record.rule_type);
            let violation_score = rule_weight;

            weighted_sum += violation_score * time_weight;
            total_weight += time_weight;
        }

        if total_weight > 0.0 {
            weighted_sum / total_weight
        } else {
            0.0
        }
    }

    // ✅ NEW: Trend calculation
    fn update_trend(&mut self) {
        let previous_score = self.previous_threat_score;
        let current_score = self.current_threat_score;
        let threshold = 2.0; // Minimum change to show trend

        if current_score > previous_score + threshold {
            self.score_trend = ScoreTrend::Up;
        } else if current_score < previous_score - threshold {
            self.score_trend = ScoreTrend::Down;
        } else {
            self.score_trend = ScoreTrend::Stable;
        }

        // Update previous score every hour
        let now = Self::current_timestamp();
        if now - self.last_update_time >= 3600 {
            self.previous_threat_score = self.current_threat_score;
            self.last_update_time = now;
        }
    }

    // ✅ NEW: Get trend information for frontend
    pub fn get_threat_trend_info(&self) -> (ScoreTrend, String, String) {
        let (arrow, color) = match self.score_trend {
            ScoreTrend::Up => ("↑", "red"),
            ScoreTrend::Down => ("↓", "green"),
            ScoreTrend::Stable => ("→", "gray"),
        };

        (self.score_trend.clone(), arrow.to_string(), color.to_string())
    }

    async fn send_ocr_live_data(
        &self,
        ocr_data: &OcrData,
        screenshot_path: &str,
        communicator: &ServerCommunicator,
        token: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Get trend info
        let (_, threat_arrow, trend_color) = self.get_threat_trend_info();

        let live_data = OcrLiveData {
            agent_id: self.agent_id,
            timestamp: chrono::Utc::now().to_rfc3339(),
            screenshot_path: screenshot_path.to_string(),
            extracted_text: if ocr_data.text.len() > 500 {
                format!("{}...", &ocr_data.text[..500])
            } else {
                ocr_data.text.clone()
            },
            content_type: self.determine_content_type(&ocr_data.context),
            language: ocr_data.context.language.clone(),
            readability_score: ocr_data.context.readability_score,
            threat_score: self.calculate_current_threat_score(),
            violation_count: self.violation_count,
            primary_context: self.analyze_context_patterns().primary_context,
            active: true,
        };

        communicator.send_ocr_live_data(self.agent_id, token, &live_data).await
    }

    async fn send_empty_ocr_update(
        &self,
        screenshot_path: &str,
        communicator: &ServerCommunicator,
        token: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Get trend info
        // let (_, threat_arrow, trend_color) = self.get_threat_trend_info();

        let live_data = OcrLiveData {
            agent_id: self.agent_id,
            timestamp: chrono::Utc::now().to_rfc3339(),
            screenshot_path: screenshot_path.to_string(),
            extracted_text: "No text detected".to_string(),
            content_type: "empty".to_string(),
            language: "unknown".to_string(),
            readability_score: 0.0,
            threat_score: self.calculate_current_threat_score(), // Use current score, not 0
            violation_count: self.violation_count,
            primary_context: "EMPTY".to_string(),
            active: true,
        };

        communicator.send_ocr_live_data(self.agent_id, token, &live_data).await
    }

    async fn send_ocr_violation(
        &mut self,
        violation: &Violation,
        screenshot_path: &str,
         screenshot_timestamp: &DateTime<Utc>,  // For reference (maybe store in DB)
    detection_timestamp: &DateTime<Utc>,  
        communicator: &ServerCommunicator,
        token: &str
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let ocr_violation = OcrViolation {
            agent_id: self.agent_id,
            timestamp: detection_timestamp.to_rfc3339(), 
            rule_type: violation.rule_type.clone(),
            matched_text: violation.matched_text.clone(),
            confidence: violation.confidence,
            threat_score: violation.context_confidence * 100.0,
            context_confidence: violation.context_confidence,
            screenshot_path: screenshot_path.to_string(),
        };

        // ⭐ CALL API AND GET ID
        let saved_id = communicator.send_ocr_violation(self.agent_id, token, &ocr_violation).await?;

        println!("📌 Saved violation from backend = {} at {}", saved_id , detection_timestamp.to_rfc3339());

        // ⭐ STORE VIOLATION ID
        self.last_violation_ids.push(saved_id);
        Ok(saved_id)
    }

    fn determine_content_type(&self, context: &TextContext) -> String {
        if context.is_financial {
            "financial".to_string()
        } else if context.is_business {
            "business".to_string()
        } else if context.is_technical {
            "technical".to_string()
        } else if context.is_personal {
            "personal".to_string()
        } else {
            "general".to_string()
        }
    }

    pub fn print_banner(&self) {
        println!("🚀 Starting Advanced Security Monitor with NLP Enhancement...");
        println!("💻 Device: {}", self.device_addr);
        println!("🔗 MAC: {}", self.mac_addr);
        println!("⏰ OCR Interval: 5s");
        println!("📊 Certificate Generation: Every 60 seconds");
        println!("🤖 LLM Threat Assessment: Enabled");
        println!("🧠 NLP Context Awareness: Enabled");
        println!("📈 Performance Monitoring: Active");
        println!("🗑️ Cleanup: Screenshots (30s), Certificates (5m), Logs (10m)");
        println!("🔧 Rule Engine: Enhanced with Context-Aware Validation");
        println!("{}", "=".repeat(60));
    }

    pub fn should_run_maintenance(&self) -> bool {
        let current_time = Self::current_timestamp();
        current_time - self.last_certificate_time >= 60
    }

    

    /// Process a single frame: screenshot → OCR → rule engine → logs → realtime.
    // pub async fn process_frame(
    //     &mut self,
    //     communicator: &ServerCommunicator,
    //     token: &str
    // ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    //     let start_time = std::time::Instant::now();
    //     // 1. Capture screenshot
    //     let img = capture_screenshot()?;
        
    //     let timestamp = Utc::now();

    //      self.rule_engine.reset_for_screenshot();

    //     // 2. Save screenshot and build metadata
    //     let ss_path = self.save_screenshot(&img, &timestamp)?;
    //     self.last_screenshot_data = Some(ScreenshotData {
    //         path: ss_path.clone(),
    //         dimensions: (img.width(), img.height()),
    //         size_kb: (fs::metadata(&ss_path)?.len() as f32) / 1024.0,
    //         preview_url: self.create_thumbnail_base64(&img)?,
    //     });

    //     println!("🖥️ Captured screenshot: {}x{}", img.width(), img.height());
    // println!("🔄 Reset deduplication cache for new screenshot");
    
    //     // 3. OCR with multiple preprocessing strategies
    //     let ocr_result = self.try_ocr_with_preprocessing(&img);
    //     let processing_time = start_time.elapsed().as_secs_f64();

    //     let ocr_data = match ocr_result {
    //         Ok(data) if !data.text.trim().is_empty() => {
    //             self.performance_metrics.record_processing_time(processing_time, true);
    //             data
    //         }
    //         Ok(_) => {
    //             self.performance_metrics.record_processing_time(processing_time, false);
    //             println!("⚠️ No text extracted from screenshot");

    //             // SEND EMPTY OCR FRAME INSTEAD OF RETURNING EARLY
    //             self.send_empty_ocr_update(&ss_path, communicator, token).await?;
    //             return Ok(());
    //         }
    //         Err(e) => {
    //             self.performance_metrics.record_processing_time(processing_time, false);
    //             eprintln!("❌ OCR processing error: {}", e);
    //             return Ok(());
    //         }
    //     };

    //     // 4. Store context history
    //     self.context_history.push(ocr_data.context.clone());
    //     if self.context_history.len() > 10 {
    //         self.context_history.remove(0);
    //     }

    //     println!("🔍 Enhanced OCR extracted {} characters", ocr_data.text.len());
    //     println!("📊 NLP Analysis: {}", self.format_context_summary(&ocr_data.context));

    //     if self.performance_metrics.total_frames_processed % 20 == 0 {
    //         self.print_performance_stats();
    //     }

    //     // 5. Rule engine: full-text + per-word
    //     let (full_violations, word_violations) = self.rule_engine.check_ocr_data(
    //         &ocr_data.text,
    //         &ocr_data
    //     );

    //     let all_violations: Vec<_> = full_violations
    //         .into_iter()
    //         .chain(word_violations.into_iter())
    //         .collect();

    //     // 6. Realtime violation updates + logging
    //     if !all_violations.is_empty() {
    //         // Update threat score with new violations
    //         self.update_threat_score_with_violations(&all_violations);

    //         // // Send each violation to server
    //         // for violation in &all_violations {
    //         //     self.send_ocr_violation(violation, &ss_path, &timestamp, communicator, token).await?;
    //         // }

    //         // Send violations with rate limiting
    //         self.send_violations_with_rate_limit(
    //             &all_violations,
    //             &ss_path,
    //             &timestamp,
    //             communicator,
    //             token
    //         ).await?;
            
    //         // // Log + increment counters
    //         self.process_violations(
    //             &all_violations,
    //             &ss_path,
    //             &ocr_data.text,
    //             &timestamp,
    //             &ocr_data.context
    //         ).await?;

    //         // Send OCR live data with updated threat score
    //         self.send_ocr_live_data(&ocr_data, &ss_path, communicator, token).await?;
    //     } else {
    //         println!("✅ Scan clean - {} violations detected so far", self.violation_count);
    //         // Even with no violations, send OCR live data
    //         self.send_ocr_live_data(&ocr_data, &ss_path, communicator, token).await?;
    //     }

    //     Ok(())
    // }

    pub async fn process_frame(
    &mut self,
    communicator: &ServerCommunicator,
    token: &str
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let start_time = std::time::Instant::now();

    // 1. Capture screenshot
    let img = capture_screenshot()?;
     let timestamp = Utc::now();
    let screenshot_timestamp = Utc::now();
    self.last_screenshot_time = Some(timestamp);
    self.rule_engine.reset_for_screenshot();

    // 2. Save screenshot and build metadata
    let ss_path = self.save_screenshot(&img, &screenshot_timestamp)?;

    self.last_screenshot_data = Some(ScreenshotData {
        path: ss_path.clone(),
        dimensions: (img.width(), img.height()),
        size_kb: (fs::metadata(&ss_path)?.len() as f32) / 1024.0,
        preview_url: self.create_thumbnail_base64(&img)?,
         timestamp: timestamp,
    });

    println!("🖥️ Captured screenshot: {}x{}", img.width(), img.height());
    println!("🔄 Reset deduplication cache for new screenshot");

    // 3. OCR with multiple preprocessing strategies
    let ocr_result = self.try_ocr_with_preprocessing(&img);
    let processing_time = start_time.elapsed().as_secs_f64();

    let ocr_data = match ocr_result {
        Ok(data) if !data.text.trim().is_empty() => {
            self.performance_metrics.record_processing_time(processing_time, true);
            data
        }
        Ok(_) => {
            self.performance_metrics.record_processing_time(processing_time, false);
            println!("⚠️ No text extracted from screenshot");

            // SEND EMPTY OCR FRAME INSTEAD OF RETURNING EARLY
            self.send_empty_ocr_update(&ss_path, communicator, token).await?;
            return Ok(());
        }
        Err(e) => {
            self.performance_metrics.record_processing_time(processing_time, false);
            eprintln!("❌ OCR processing error: {}", e);
            return Ok(());
        }
    };

    // 4. Store context history
    self.context_history.push(ocr_data.context.clone());
    if self.context_history.len() > 10 {
        self.context_history.remove(0);
    }

    println!("🔍 Enhanced OCR extracted {} characters", ocr_data.text.len());
    println!("📊 NLP Analysis: {}", self.format_context_summary(&ocr_data.context));

    if self.performance_metrics.total_frames_processed % 20 == 0 {
        self.print_performance_stats();
    }

    // 5. Rule engine: full-text + per-word
    let (full_violations, word_violations) = self.rule_engine.check_ocr_data(
        &ocr_data.text,
        &ocr_data
    );

    let all_violations: Vec<_> = full_violations
        .into_iter()
        .chain(word_violations.into_iter())
        .collect();

    // 6. Realtime violation updates + logging
    if !all_violations.is_empty() {
        let detection_timestamp = Utc::now();
        // Update threat score with new violations
        self.update_threat_score_with_violations(&all_violations);

         let current_threat_score = self.calculate_current_threat_score();

        // Send violations with rate limiting
        self.send_violations_with_rate_limit(
            &all_violations,
            &ss_path,
            &screenshot_timestamp,   
            &detection_timestamp,
            communicator,
            token
        ).await?;

          // ⭐ SEND HIGH THREAT ALERTS - Use the current threat score from monitor
    if current_threat_score >= 70.0 {
        // Get hostname and username
        let hostname = whoami::devicename();
        let username = whoami::username();
        
        // For each violation, create an alert
        for violation in &all_violations {
            // Convert Violation to OcrViolation for the alert
            let ocr_violation = OcrViolation {
                agent_id: self.agent_id,
                timestamp: timestamp.to_rfc3339(),
                rule_type: violation.rule_type.clone(),
                matched_text: violation.matched_text.clone(),
                confidence: violation.confidence,
                threat_score: current_threat_score, // Use the monitor's current threat score
                context_confidence: violation.context_confidence,
                screenshot_path: ss_path.clone(),
            };
            
            // Send the high threat alert
            if let Err(e) = communicator.send_ocr_high_threat_alert(
                self.agent_id,
                token,
                &ocr_violation,
                &hostname,
                &username,
            ).await {
                log::error!("Failed to send OCR high threat alert: {}", e);
            } else {
                log::info!("✅ OCR high threat alert sent for violation type: {} (score: {:.1})", 
                          violation.rule_type, current_threat_score);
            }
        }
    }
    
        // Log + increment counters
        self.process_violations(
            &all_violations,
            &ss_path,
            &ocr_data.text,
            &timestamp,
            &ocr_data.context
        ).await?;

        // Send OCR live data with updated threat score
        self.send_ocr_live_data(&ocr_data, &ss_path, communicator, token).await?;
    } else {
        println!("✅ Scan clean - {} violations detected so far", self.violation_count);
        // Even with no violations, send OCR live data
        self.send_ocr_live_data(&ocr_data, &ss_path, communicator, token).await?;
    }

    Ok(())
}

    /// Get current OCR status with correct last screenshot time
    pub async fn get_ocr_status_update(&self) -> OcrStatusUpdate {
        let hostname = whoami::devicename();
        let username = whoami::username();
        
        // Get the trend info   
        let (_, threat_arrow, trend_color) = self.get_threat_trend_info();
        
        // Format the last screenshot time properly
         // ✅ Get the actual last screenshot time from the monitor
        let last_screenshot_time = if let Some(screenshot_data) = &self.last_screenshot_data {
            // Extract timestamp from the screenshot path or use current time
            // Since we don't store the timestamp separately, we'll parse from path
            Self::extract_timestamp_from_path(&screenshot_data.path)
                .unwrap_or_else(|| Utc::now().to_rfc3339())
        } else {
            Utc::now().to_rfc3339()
        };
        
        OcrStatusUpdate {
            agent_id: self.agent_id,
            ocr_enabled: true, // or get from config
            last_screenshot_time,
            threat_score: self.calculate_current_threat_score(),
            threat_arrow,
            trend_color,
            violations_last_24h: self.get_violations_last_24h(), // You need to implement this
            agent_hostname: hostname,
            username,
        }
    }
    
      /// Helper to count violations in last 24 hours
    fn get_violations_last_24h(&self) -> u32 {
        let now = Self::current_timestamp();
        let twenty_four_hours_ago = now.saturating_sub(24 * 60 * 60);
        
        self.violation_history_24h
            .iter()
            .filter(|(_, timestamp)| *timestamp >= twenty_four_hours_ago)
            .count() as u32
    }

      pub fn extract_timestamp_from_path(path: &str) -> Option<String> {
        // Your screenshot paths look like: 
        // security_monitor/screenshots/2026-02-13/10/screenshot_20260213_104746.png
        
        use regex::Regex;
        
        // Try to extract timestamp from filename
        let re = Regex::new(r"screenshot_(\d{8})_(\d{6})").ok()?;
        
        if let Some(caps) = re.captures(path) {
            let date = caps.get(1)?.as_str();  // 20260213
            let time = caps.get(2)?.as_str();  // 104746
            
            // Format: 2026-02-13T10:47:46
            let year = &date[0..4];
            let month = &date[4..6];
            let day = &date[6..8];
            let hour = &time[0..2];
            let minute = &time[2..4];
            let second = &time[4..6];
            
            Some(format!("{}-{}-{}T{}:{}:{}.000000", 
                year, month, day, hour, minute, second))
        } else {
            None
        }
    }
    // Update process_violations to add violations to history
    async fn process_violations(
        &mut self,
        violations: &[Violation],
        ss_path: &str,
        text: &str,
        timestamp: &DateTime<Utc>,
        context: &TextContext
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let new_violations = violations.len() as u32;
        self.violation_count = self.violation_count.saturating_add(new_violations);

        let mut rule_violations: HashMap<String, HashSet<String>> = HashMap::new();
        let mut hits = Vec::new();

        for violation in violations {
            hits.push(Hit {
                rule: violation.rule_type.clone(),
                x: violation.x,
                y: violation.y,
                flagged_text: violation.matched_text.clone(),
                context_confidence: violation.context_confidence,
                contextual_evidence: violation.contextual_clues.clone(),
            });

            rule_violations
                .entry(violation.rule_type.clone())
                .or_insert_with(HashSet::new)
                .insert(violation.matched_text.clone());
        }

        let log_entry = LogEntry {
            event: "violation".to_string(),
            timestamp: timestamp.to_rfc3339(),
            device: self.device_addr.clone(),
            mac: self.mac_addr.clone(),
            violation_count: self.violation_count,
            rules_detected: rule_violations.len(),
            screenshot: ss_path.to_string(),
            hits: hits.clone(),
            text_sample: if text.len() > 200 {
                format!("{}...", &text[..200])
            } else {
                text.to_string()
            },
            rule_engine_used: true,
            ocr_quality: self.assess_ocr_quality(text, context),
            nlp_context: context.clone(),
        };

        self.write_log(&log_entry)?;
        self.accumulated_logs.push(log_entry);

        println!(
            "🚨 CONTEXT-AWARE VIOLATION {}: {} unique rules detected",
            self.violation_count,
            rule_violations.len()
        );

        for (rule_type, texts) in &rule_violations {
            println!("   📋 {} violations:", rule_type);
            for t in texts {
                println!("      • '{}'", t);
            }
        }

        self.print_context_analysis(violations, context);

        Ok(())
    }

    // Rest of the methods remain the same...
    // [Previous code for other methods continues here...]

    pub async fn maintenance_check(
        &mut self,
        communicator_arc: &Arc<RwLock<ServerCommunicator>>,
        token: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let current_time = Self::current_timestamp();

        // 1. Periodic certificate generation
        if current_time - self.last_certificate_time >= 60 {
            let comm_arc = self.communicator.clone();
            let token = {
                let t = self.token.lock().await;
                t.clone()
            };

            self.generate_and_save_certificate(communicator_arc, &token).await?;
            self.last_certificate_time = current_time;
        }

        // 2. Periodic log shipping
        if current_time - self.start_time >= LOG_RETENTION {
            self.send_logs_to_server().await?;
            self.start_time = current_time;
        }

        // Cleanup operations
        let (ss_files, ss_space) = self.cleanup_old_screenshots()?;
        let (cert_files, cert_space) = self.cleanup_old_certificates()?;
        let (log_files, log_space) = self.cleanup_old_logs()?;

        let cleaned_count = ss_files + cert_files + log_files;
        let space_freed = ss_space + cert_space + log_space;

        // Send certificate summary...
        if let Some(certificate) = &self.last_certificate {
            if let Some(tx) = &self.realtime_tx {
                let summary = CertificateSummary {
                    certificate_id: certificate.certificate_id.clone(),
                    generation_time: certificate.assessment_time.clone(),
                    threat_score: certificate.threat_score,
                    threat_level: certificate.threat_level.clone(),
                    total_violations: certificate.total_violations,
                    primary_context: certificate.context_analysis.primary_context.clone(),
                    color_code: certificate.color_code.clone(),
                    emoji: certificate.emoji.clone(),
                    download_url: format!(
                        "certificates/{}_{}.json",
                        certificate.user_device,
                        certificate.assessment_time
                    ),
                };

                let _ = tx.send(RealtimeUpdate {
                    update_type: UpdateType::CertificateGenerated,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    agent_id: self.agent_id,
                    data: UpdateData::Certificate(summary),
                });
            }
        }

        // Send maintenance log...
        if let Some(tx) = &self.realtime_tx {
            let _ = tx.send(RealtimeUpdate {
                update_type: UpdateType::MaintenanceCompleted,
                timestamp: chrono::Utc::now().to_rfc3339(),
                agent_id: self.agent_id,
                data: UpdateData::Maintenance(MaintenanceLog {
                    action: "Scheduled cleanup".to_string(),
                    details: format!("Cleaned {} old files", cleaned_count),
                    files_cleaned: cleaned_count,
                    space_freed_mb: space_freed,
                }),
            });
        }

        Ok(())
    }

    // ---------- PUBLIC HELPERS ----------

    pub fn get_last_screenshot_data(&self) -> Option<ScreenshotData> {
        self.last_screenshot_data.clone()
    }

    fn get_current_settings(&self) -> MonitorSettings {
        MonitorSettings {
            ocr_interval: 5,
            cleanup_screenshots_after: 30,
            cleanup_certificates_after: 300,
            cleanup_logs_after: 600,
            llm_enabled: true,
        }
    }

    pub fn get_status(&self) -> AgentStatus {
        AgentStatus {
            enabled: true,
            last_activity: chrono::Utc::now().to_rfc3339(),
            violations_today: self.violation_count,
            screenshots_today: self.performance_metrics.total_frames_processed as u32,
            certificates_today: self.certificates_generated_today,
            current_settings: self.get_current_settings(),
        }
    }

    pub fn get_performance_metrics(&self) -> PerformanceUpdate {
        PerformanceUpdate {
            frames_processed: self.performance_metrics.total_frames_processed,
            text_detection_rate: self.performance_metrics.get_text_detection_rate(),
            avg_processing_time: self.performance_metrics.average_processing_time,
            cpu_usage: self.get_cpu_usage(),
            memory_usage_mb: self.get_memory_usage(),
            disk_usage_mb: self.get_disk_usage(),
        }
    }

    fn create_thumbnail_base64(
        &self,
        img: &DynamicImage
    ) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
        let thumbnail = img.resize(200, 200, image::imageops::FilterType::Lanczos3);

        let mut buffer = Vec::new();
        thumbnail.write_to(&mut std::io::Cursor::new(&mut buffer), image::ImageFormat::Png)?;

        Ok(Some(format!("data:image/png;base64,{}", general_purpose::STANDARD.encode(buffer))))
    }

    // ---------- OCR & CONTEXT HELPERS ----------

    fn format_context_summary(&self, context: &TextContext) -> String {
        format!(
            "Lang: {}, Financial: {}, Business: {}, Tech: {}, Personal: {}, Readability: {:.1}",
            context.language,
            context.is_financial,
            context.is_business,
            context.is_technical,
            context.is_personal,
            context.readability_score
        )
    }

    fn try_ocr_with_preprocessing(
        &mut self,
        img: &DynamicImage
    ) -> Result<OcrData, Box<dyn std::error::Error>> {
        type PreprocessStrategy = fn(&DynamicImage) -> DynamicImage;

        let strategies: Vec<(&str, PreprocessStrategy)> = vec![
            ("document", document_preprocess_image),
            ("advanced", advanced_preprocess_image),
            ("original", |img: &DynamicImage| img.clone())
        ];

        let mut best_result: Option<OcrData> = None;
        let mut best_score = 0usize;
        let mut best_strategy = "none";

        for (name, strategy) in &strategies {
            let processed_img = strategy(img);
            match self.ocr_processor.extract_text(&processed_img) {
                Ok(data) if !data.text.trim().is_empty() => {
                    let score = self.calculate_ocr_quality(&data);
                    if score > best_score {
                        best_score = score;
                        best_result = Some(data);
                        best_strategy = name;
                    }
                }
                Ok(_) => {
                    continue;
                }
                Err(e) => {
                    eprintln!("❌ OCR strategy '{}' failed: {}", name, e);
                    continue;
                }
            }
        }

        if let Some(result) = best_result {
            println!("🎯 Best OCR strategy: {} (score: {})", best_strategy, best_score);
            Ok(result)
        } else {
            Err("All OCR strategies failed to extract meaningful text".into())
        }
    }

    fn calculate_ocr_quality(&self, data: &OcrData) -> usize {
        let mut score = data.text.len();

        if !data.words.is_empty() {
            let avg_conf: f32 =
                data.words
                    .iter()
                    .map(|w| w.confidence)
                    .sum::<f32>() / (data.words.len() as f32);

            if avg_conf > 0.7 {
                score += 100;
            } else if avg_conf > 0.5 {
                score += 50;
            }
        }

        if data.context.readability_score > 30.0 && data.context.readability_score < 80.0 {
            score += 50;
        }

        if data.context.sentence_count > 1 {
            score += 30;
        }

        if data.text.len() < 20 {
            score = score.saturating_sub(50);
        }

        score
    }

    fn assess_ocr_quality(&self, text: &str, context: &TextContext) -> String {
        if text.len() < 10 {
            return "very_low".to_string();
        }

        let mut score = 0;

        if text.len() > 100 {
            score += 3;
        } else if text.len() > 50 {
            score += 2;
        } else if text.len() > 20 {
            score += 1;
        }

        if context.readability_score > 50.0 && context.readability_score < 80.0 {
            score += 2;
        }

        if context.sentence_count > 2 {
            score += 2;
        }

        match score {
            5..=7 => "high".to_string(),
            3..=4 => "medium".to_string(),
            1..=2 => "low".to_string(),
            _ => "very_low".to_string(),
        }
    }

    fn print_context_analysis(&self, violations: &[Violation], context: &TextContext) {
        println!("   📊 Context Analysis:");
        println!("      Language: {}", context.language);
        println!("      Financial Context: {}", context.is_financial);
        println!("      Business Context: {}", context.is_business);
        println!("      Technical Context: {}", context.is_technical);
        println!("      Personal Context: {}", context.is_personal);
        println!("      Contains Names: {}", context.contains_names);
        println!("      Sentences: {}", context.sentence_count);
        println!("      Avg Sentence Length: {:.1}", context.avg_sentence_length);
        println!("      Readability Score: {:.1}", context.readability_score);

        let mut high_confidence_violations = 0;
        for violation in violations {
            if violation.context_confidence > 0.8 {
                high_confidence_violations += 1;
            }

            if !violation.contextual_clues.is_empty() {
                println!(
                    "      🔍 Contextual Clues for {} (confidence: {:.2}):",
                    violation.rule_type,
                    violation.context_confidence
                );
                for clue in &violation.contextual_clues {
                    println!("        • {}", clue);
                }
            }
        }

        println!(
            "      High Confidence Violations: {}/{}",
            high_confidence_violations,
            violations.len()
        );
    }

    fn print_performance_stats(&self) {
        let metrics = &self.performance_metrics;
        println!("📈 Performance Statistics:");
        println!("   Total Frames: {}", metrics.total_frames_processed);
        println!("   Text Detection Rate: {:.1}%", metrics.get_text_detection_rate());
        println!("   Avg Processing Time: {:.2}s", metrics.average_processing_time);
        println!("   Total Violations: {}", self.violation_count);
        println!("   Context History Size: {}", self.context_history.len());
    }

    // ---------- FILE IO & CERTIFICATES ----------

    fn save_screenshot(
        &mut self,
        img: &DynamicImage,
        timestamp: &DateTime<Utc>
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let local_time = timestamp.with_timezone(&chrono::Local);

        let date_folder = local_time.format("%Y-%m-%d").to_string();
        let hour_folder = local_time.format("%H").to_string();
        let base_dir = self.screenshots_base_dir.join(&date_folder).join(&hour_folder);

        fs::create_dir_all(&base_dir)?;

        let filename = format!("screenshot_{}.png", local_time.format("%Y%m%d_%H%M%S"));
        let full_path = base_dir.join(&filename);

        img.save_with_format(&full_path, image::ImageFormat::Png)?;

        println!("📸 Screenshot saved: {}", full_path.display());
        // ✅ Store the screenshot data with correct timestamp
        self.last_screenshot_data = Some(ScreenshotData {
             path: full_path.to_string_lossy().to_string(),
            dimensions: (img.width(), img.height()),
            size_kb: (fs::metadata(&full_path)?.len() as f32) / 1024.0,
            preview_url: self.create_thumbnail_base64(img)?,
             timestamp: *timestamp,
        });
        Ok(full_path.to_string_lossy().to_string())
    }

    fn write_log(&self, entry: &LogEntry) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        fs::create_dir_all(&self.logs_dir)?;

        let log_file = self.logs_dir.join(
            format!("security_log_{}.json", Utc::now().format("%Y%m%d_%H"))
        );

        let log_line = serde_json::to_string(entry)? + "\n";

        let mut file = fs::OpenOptions::new().create(true).append(true).open(log_file)?;

        file.write_all(log_line.as_bytes())?;

        Ok(())
    }

    async fn generate_and_save_certificate(
        &mut self,
        communicator_arc: &Arc<RwLock<ServerCommunicator>>,
        token: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!("📊 Generating enhanced threat assessment certificate...");

        let all_hits: Vec<Hit> = self.accumulated_logs
            .iter()
            .flat_map(|log| log.hits.clone())
            .collect();

        // Calculate threat score using current global score
        let current_threat_score = self.calculate_current_threat_score();
        println!("📌 Current Global Threat Score = {}", current_threat_score);

        let context_patterns = self.analyze_context_patterns();

        let certificate = self.llm_assessor.generate_certificate(
            current_threat_score, // Use global score
            &all_hits,
            &self.device_addr,
            &self.mac_addr,
            &context_patterns
        ).await?;

        println!("🎯 Final Threat Score Used = {}", certificate.threat_score);

        self.print_certificate(&certificate);
        self.save_certificate(&certificate)?;

        // Convert into API type
        let api_certificate = SecurityCertificate {
            agent_id: self.agent_id,
            assessment_time: certificate.assessment_time.clone(),
            user_device: certificate.user_device.clone(),
            threat_level: certificate.threat_level.clone(),
            threat_score: certificate.threat_score,
            total_violations: certificate.total_violations as u32,
            primary_context: certificate.context_analysis.primary_context.clone(),
            risk_analysis: certificate.risk_analysis.clone(),
            immediate_actions: certificate.immediate_actions.clone(),
            rule_breakdown: certificate.rule_breakdown
                .iter()
                .map(|(k, v)| (k.clone(), *v as u32))
                .collect(),
            emoji: certificate.emoji.clone(),
        };

        // ---- SEND TO BACKEND ----
        let comm = communicator_arc.read().await;
        comm.send_ocr_certificate(
            self.agent_id,
            token,
            &api_certificate,
            &self.last_violation_ids
        ).await?;

        println!("📤 SENT OCR CERTIFICATE TO SERVER");

        self.last_certificate = Some(certificate.clone());
        self.certificates_generated_today += 1;

        Ok(())
    }

    fn analyze_context_patterns(&self) -> ContextAnalysis {
        if self.context_history.is_empty() {
            return ContextAnalysis {
                primary_context: "UNKNOWN".to_string(),
                risk_factors: vec!["No context data available".to_string()],
                behavioral_patterns: vec!["Initial monitoring phase".to_string()],
                confidence_score: 0.1,
            };
        }

        let financial_count = self.context_history
            .iter()
            .filter(|c| c.is_financial)
            .count();
        let business_count = self.context_history
            .iter()
            .filter(|c| c.is_business)
            .count();
        let technical_count = self.context_history
            .iter()
            .filter(|c| c.is_technical)
            .count();
        let personal_count = self.context_history
            .iter()
            .filter(|c| c.is_personal)
            .count();
        let names_count = self.context_history
            .iter()
            .filter(|c| c.contains_names)
            .count();

        let total = self.context_history.len() as f32;

        let financial_ratio = (financial_count as f32) / total;
        let business_ratio = (business_count as f32) / total;
        let technical_ratio = (technical_count as f32) / total;
        let personal_ratio = (personal_count as f32) / total;
        let names_ratio = (names_count as f32) / total;

        let primary_context = (
            if financial_ratio > 0.4 {
                "FINANCIAL"
            } else if business_ratio > 0.4 {
                "BUSINESS"
            } else if technical_ratio > 0.4 {
                "TECHNICAL"
            } else if personal_ratio > 0.4 {
                "PERSONAL"
            } else {
                "MIXED"
            }
        ).to_string();

        let mut risk_factors = Vec::new();
        if financial_ratio > 0.3 {
            risk_factors.push(
                format!("Frequent financial content ({:.1}%)", financial_ratio * 100.0)
            );
        }
        if names_ratio > 0.2 {
            risk_factors.push(
                format!("Personal information present ({:.1}%)", names_ratio * 100.0)
            );
        }
        if technical_ratio > 0.5 {
            risk_factors.push("Heavy technical content".to_string());
        }

        let mut behavioral_patterns = Vec::new();
        if self.context_history.len() >= 5 {
            behavioral_patterns.push("Established context patterns".to_string());
        }

        let avg_readability: f32 =
            self.context_history
                .iter()
                .map(|c| c.readability_score)
                .sum::<f32>() / total;

        if avg_readability < 30.0 {
            behavioral_patterns.push("Simple text content".to_string());
        } else if avg_readability > 70.0 {
            behavioral_patterns.push("Complex text content".to_string());
        }

        let confidence_score = if self.context_history.len() >= 3 {
            0.7 + ((self.context_history.len() as f32) / 10.0).min(0.3)
        } else {
            0.5
        };

        ContextAnalysis {
            primary_context,
            risk_factors,
            behavioral_patterns,
            confidence_score: confidence_score.min(1.0),
        }
    }

    async fn send_logs_to_server(
        &mut self
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.accumulated_logs.is_empty() {
            return Ok(());
        }

        println!("📤 SENDING {} LOGS TO SERVER", self.accumulated_logs.len());

        // Clone ARC (important)
        let comm_arc = self.communicator.clone();

        // Lock token safely
        let token = {
            let t = self.token.lock().await;
            t.clone()
        };

        // Generate certificate safely
        self.generate_and_save_certificate(&comm_arc, &token).await?;

        println!("   📝 Logs would be sent to security server here");

        self.accumulated_logs.clear();
        Ok(())
    }

    fn save_certificate(
        &self,
        certificate: &Certificate
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        fs::create_dir_all(&self.certificates_dir)?;

        let cert_file = self.certificates_dir.join(
            format!(
                "certificate_{}_{}.json",
                certificate.user_device,
                chrono::Utc::now().format("%Y%m%d_%H%M%S")
            )
        );

        let cert_json = serde_json::to_string_pretty(certificate)?;
        fs::write(&cert_file, cert_json)?;

        println!("💾 Certificate saved: {}", cert_file.display());
        Ok(())
    }

    fn print_certificate(&self, certificate: &Certificate) {
        println!("\n{}", "=".repeat(70));
        println!("🎯 ENHANCED THREAT ASSESSMENT CERTIFICATE GENERATED:");
        println!("{}", "=".repeat(70));
        println!("User: {} ({})", certificate.user_device, certificate.user_mac);
        println!("Time: {}", certificate.assessment_time);
        println!("Method: {}", certificate.assessment_method);
        println!("LLM Available: {}", certificate.llm_available);
        println!("Primary Context: {}", certificate.context_analysis.primary_context);
        println!(
            "Context Confidence: {:.1}%",
            certificate.context_analysis.confidence_score * 100.0
        );
        println!("Threat Level: {} {}", certificate.emoji, certificate.threat_level);
        println!("Score: {:.1}/100", certificate.threat_score);
        println!("Total Violations: {}", certificate.total_violations);
        println!("Unique Rule Types: {}", certificate.unique_rule_types);

        if !certificate.context_analysis.risk_factors.is_empty() {
            println!("\nRisk Factors:");
            for factor in &certificate.context_analysis.risk_factors {
                println!("  • {}", factor);
            }
        }

        println!("\nRisk Analysis: {}", certificate.risk_analysis);
        println!("Behavior Insights: {}", certificate.behavior_insights);

        println!("\nImmediate Actions:");
        for action in &certificate.immediate_actions {
            println!("  • {}", action);
        }

        println!("\nTraining Recommendations:");
        for training in &certificate.training_recommendations {
            println!("  • {}", training);
        }

        if !certificate.rule_breakdown.is_empty() {
            println!("\nRule Violation Breakdown:");
            for (rule, count) in &certificate.rule_breakdown {
                println!("  • {}: {}", rule, count);
            }
        }

        println!("{}", "=".repeat(70));
    }

    // ---------- CLEANUP HELPERS ----------

    fn cleanup_old_screenshots(
        &self
    ) -> Result<(u32, f32), Box<dyn std::error::Error + Send + Sync>> {
        let screenshots_dir = &self.screenshots_base_dir;
        if !screenshots_dir.exists() {
            return Ok((0, 0.0));
        }

        let now = SystemTime::now();
        let max_age = Duration::from_secs(30);
        let mut files_cleaned = 0u32;
        let mut space_freed_bytes: u64 = 0;

        fn cleanup_directory(
            dir: &Path,
            now: SystemTime,
            max_age: Duration,
            files_cleaned: &mut u32,
            space_freed_bytes: &mut u64
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            if dir.is_dir() {
                for entry in fs::read_dir(dir)? {
                    let entry = entry?;
                    let path = entry.path();

                    if path.is_dir() {
                        cleanup_directory(&path, now, max_age, files_cleaned, space_freed_bytes)?;
                        if fs::read_dir(&path)?.next().is_none() {
                            fs::remove_dir(&path)?;
                            println!("🗑️ Deleted empty directory: {}", path.display());
                        }
                    } else if path.is_file() {
                        if let Ok(metadata) = fs::metadata(&path) {
                            if let Ok(modified) = metadata.modified() {
                                if
                                    now.duration_since(modified).unwrap_or(Duration::from_secs(0)) >
                                    max_age
                                {
                                    *files_cleaned += 1;
                                    *space_freed_bytes += metadata.len();
                                    fs::remove_file(&path)?;
                                    println!("🗑️ Deleted old screenshot: {}", path.display());
                                }
                            }
                        }
                    }
                }
            }
            Ok(())
        }

        cleanup_directory(
            screenshots_dir,
            now,
            max_age,
            &mut files_cleaned,
            &mut space_freed_bytes
        )?;

        Ok((files_cleaned, (space_freed_bytes as f32) / (1024.0 * 1024.0)))
    }

    fn cleanup_old_certificates(
        &self
    ) -> Result<(u32, f32), Box<dyn std::error::Error + Send + Sync>> {
        let certificates_dir = &self.certificates_dir;
        if !certificates_dir.exists() {
            return Ok((0, 0.0));
        }

        let now = SystemTime::now();
        let max_age = Duration::from_secs(300);
        let mut files_cleaned = 0u32;
        let mut space_freed_bytes: u64 = 0;

        if let Ok(entries) = fs::read_dir(certificates_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
                    if let Ok(metadata) = fs::metadata(&path) {
                        if let Ok(modified) = metadata.modified() {
                            if
                                now.duration_since(modified).unwrap_or(Duration::from_secs(0)) >
                                max_age
                            {
                                files_cleaned += 1;
                                space_freed_bytes += metadata.len();
                                fs::remove_file(&path)?;
                                println!("🗑️ Deleted old certificate: {}", path.display());
                            }
                        }
                    }
                }
            }
        }

        Ok((files_cleaned, (space_freed_bytes as f32) / (1024.0 * 1024.0)))
    }

    fn cleanup_old_logs(&self) -> Result<(u32, f32), Box<dyn std::error::Error + Send + Sync>> {
        let logs_dir = &self.logs_dir;
        if !logs_dir.exists() {
            return Ok((0, 0.0));
        }

        let now = SystemTime::now();
        let max_age = Duration::from_secs(600);
        let mut files_cleaned = 0u32;
        let mut space_freed_bytes: u64 = 0;

        if let Ok(entries) = fs::read_dir(logs_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
                    if let Ok(metadata) = fs::metadata(&path) {
                        if let Ok(modified) = metadata.modified() {
                            if
                                now.duration_since(modified).unwrap_or(Duration::from_secs(0)) >
                                max_age
                            {
                                files_cleaned += 1;
                                space_freed_bytes += metadata.len();
                                fs::remove_file(&path)?;
                                println!("🗑️ Deleted old log: {}", path.display());
                            }
                        }
                    }
                }
            }
        }

        Ok((files_cleaned, (space_freed_bytes as f32) / (1024.0 * 1024.0)))
    }

    // ---------- SYSTEM METRICS ----------

    fn get_cpu_usage(&self) -> f32 {
        let mut sys = System::new_all();
        sys.refresh_all();

        let cpus = sys.cpus();
        if cpus.is_empty() {
            return 0.0;
        }

        let sum: f32 = cpus
            .iter()
            .map(|c| c.cpu_usage())
            .sum();
        sum / (cpus.len() as f32)
    }

    fn get_memory_usage(&self) -> f32 {
        let mut sys = System::new_all();
        sys.refresh_memory();

        // sysinfo returns in KiB
        (sys.used_memory() as f32) / 1024.0
    }

    fn get_disk_usage(&self) -> f32 {
        let disks = Disks::new_with_refreshed_list();

        let mut used_bytes: u64 = 0;
        let mut total_bytes: u64 = 0;

        for disk in disks.list() {
            let total = disk.total_space();
            let available = disk.available_space();

            total_bytes += total;
            used_bytes += total.saturating_sub(available);
        }

        if total_bytes == 0 {
            return 0.0;
        }

        ((used_bytes as f32) / (total_bytes as f32)) * 100.0
    }

    // ---------- STATIC HELPERS ----------

    fn get_device_addr() -> String {
        local_ipaddress::get().unwrap_or_else(|| "0.0.0.0".to_string())
    }

    fn get_mac_addr() -> String {
        match mac_address::get_mac_address() {
            Ok(Some(addr)) => addr.to_string(),
            Ok(None) => "00:00:00:00:00:00".to_string(),
            Err(_) => "00:00:00:00:00:00".to_string(),
        }
    }

    fn current_timestamp() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}
