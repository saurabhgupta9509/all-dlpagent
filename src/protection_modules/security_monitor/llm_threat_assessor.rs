// LLM-assisted and rule-based threat certificate generator.
// Integrates with Ollama when available, otherwise falls back to deterministic scoring.
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use reqwest;
use crate::protection_modules::security_monitor::types::{Certificate, Hit, ContextAnalysis};

const OLLAMA_BASE_URL: &str = "http://localhost:11434";
const MODEL_NAME: &str = "llama3.2:3b";

#[derive(Debug, Clone)]
// Tracks HTTP client state and whether LLM integration is currently usable.
pub struct LLMThreatAssessor {
    client: reqwest::Client,
    llm_available: bool,
}

#[derive(Debug, Serialize)]
struct OllamaRequest {
    model: String,
    prompt: String,
    stream: bool,
    options: OllamaOptions,
}

#[derive(Debug, Serialize)]
struct OllamaOptions {
    temperature: f32,
    top_p: f32,
    num_ctx: i32,
}

#[derive(Debug, Deserialize)]
struct OllamaResponse {
    response: String,
}

impl LLMThreatAssessor {
    pub fn new() -> Self {
        let client = reqwest::Client::new();
        let llm_available = false;
        
        Self {
            client,
            llm_available,
        }
    }

    // Probes Ollama server to determine if enhanced assessment can be used.
    pub async fn check_availability(&mut self) -> bool {
        match self.client.get(&format!("{}/api/tags", OLLAMA_BASE_URL))
            .timeout(std::time::Duration::from_secs(5))
            .send().await {
            Ok(response) if response.status().is_success() => {
                self.llm_available = true;
                println!("✅ Ollama is available for enhanced threat assessment");
                true
            }
            _ => {
                println!("❌ Ollama is not available. Using rule-based assessment only.");
                self.llm_available = false;
                false
            }
        }
    }

    // Orchestrates certificate generation using LLM when possible,
    // otherwise computes a deterministic rule-based assessment.
    pub async fn generate_certificate(
        &mut self, 
        avg_threat_score: f32,
        hits: &[Hit],
        device_addr: &str,
        mac_addr: &str,
        context_analysis: &ContextAnalysis,
    ) -> Result<Certificate, Box<dyn std::error::Error  + Send + Sync>> {
        let total_violations = hits.len();
        //  let base_score = avg_threat_score;
        if !self.llm_available {
            self.check_availability().await;
        }

        // if self.llm_available && total_violations > 0 {
        //     match self.generate_llm_assessment(hits, device_addr, mac_addr, context_analysis).await 
        //     {   
        //         Ok(certificate) => return Ok(certificate),
        //         Err(e) => {
        //             eprintln!("LLM assessment failed: {}, using rule-based fallback", e);
        //         }
        //     }
        // }
         if self.llm_available && total_violations > 0 {
        if let Ok(mut certificate) =
            self.generate_llm_assessment(hits, device_addr, mac_addr, context_analysis).await 
        {
            // ⭐ Unify threat scoring — CORRECT FIX ⭐
                certificate.threat_score = certificate.threat_score.max(avg_threat_score);

                certificate.threat_level = determine_threat_level(certificate.threat_score);
                
                return Ok(certificate);
            }
        }
         // Rule-based fallback
        let mut cert = self.generate_rule_based_assessment(hits, device_addr, mac_addr, context_analysis);

        // Merge avg score
        cert.threat_score = cert.threat_score.max(avg_threat_score);
        cert.threat_level = determine_threat_level(cert.threat_score);

        Ok(cert)
        // Ok(self.generate_rule_based_assessment(hits, device_addr, mac_addr, context_analysis))
    }

    // Builds prompt, sends request to Ollama, and converts model output into a certificate.
    async fn generate_llm_assessment(
        &self,
        hits: &[Hit],
        device_addr: &str,
        mac_addr: &str,
        context_analysis: &ContextAnalysis,
    ) -> Result<Certificate, Box<dyn std::error::Error>> {
        let violation_summary: String = hits.iter()
            .map(|hit| format!("- {} (context confidence: {:.2})", hit.rule, hit.context_confidence))
            .collect::<Vec<String>>()
            .join("\n");

        let unique_rules: HashSet<String> = hits.iter()
            .map(|hit| hit.rule.clone())
            .collect();

        let prompt = format!(
            "As a cybersecurity expert with NLP context awareness, analyze these security violations:\n\n\
            USER: {}\n\
            PRIMARY CONTEXT: {}\n\
            RISK FACTORS: {}\n\
            TOTAL VIOLATIONS: {}\n\
            CONTEXT CONFIDENCE ANALYSIS:\n\
            {}\n\n\
            Provide a JSON assessment with this exact structure:\n\
            {{\n\
                \"threat_score\": 0-100,\n\
                \"threat_level\": \"NO_THREAT|LOW_THREAT|MEDIUM_THREAT|HIGH_THREAT|CRITICAL_THREAT\",\n\
                \"risk_analysis\": \"context-aware risk summary considering the primary context\",\n\
                \"behavior_insights\": \"what the context and violations suggest about user behavior\",\n\
                \"immediate_actions\": [\"context-aware action1\", \"action2\"],\n\
                \"training_recommendations\": [\"context-aware training1\", \"training2\"]\n\
            }}\n\n\
            Consider violation severity, frequency, context confidence scores, and the primary context type.",
            device_addr, 
            context_analysis.primary_context,
            context_analysis.risk_factors.join(", "),
            hits.len(), 
            violation_summary
        );

        let request = OllamaRequest {
            model: MODEL_NAME.to_string(),
            prompt,
            stream: false,
            options: OllamaOptions {
                temperature: 0.3,
                top_p: 0.9,
                num_ctx: 2048,
            },
        };

        let response = self.client
            .post(&format!("{}/api/generate", OLLAMA_BASE_URL))
            .json(&request)
            .timeout(std::time::Duration::from_secs(60))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Ollama API returned status: {}", response.status()).into());
        }

        let ollama_response: OllamaResponse = response.json().await?;
        
        let json_str = extract_json_from_response(&ollama_response.response)
            .ok_or("Failed to extract JSON from LLM response")?;
        
        let assessment: LLMAssessment = serde_json::from_str(json_str)?;

        let rule_breakdown: HashMap<String, usize> = hits.iter()
            .fold(HashMap::new(), |mut acc, hit| {
                *acc.entry(hit.rule.clone()).or_insert(0) += 1;
                acc
            });

        let threat_level_clone = assessment.threat_level.clone();
        let (color_code, emoji) = get_threat_level_style(&threat_level_clone);

        Ok(Certificate {
            certificate_id: format!("THREAT_CERT_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S")),
            user_device: device_addr.to_string(),
            user_mac: mac_addr.to_string(),
            assessment_time: chrono::Utc::now().to_rfc3339(),
            assessment_method: "NLP-Enhanced LLM Assessment".to_string(),
            llm_available: true,
            threat_score: assessment.threat_score,
            threat_level: assessment.threat_level,
            risk_analysis: assessment.risk_analysis,
            behavior_insights: assessment.behavior_insights,
            immediate_actions: assessment.immediate_actions,
            training_recommendations: assessment.training_recommendations,
            total_violations: hits.len(),
            unique_rule_types: unique_rules.len(),
            rule_breakdown: rule_breakdown,
            color_code: color_code.to_string(),
            emoji: emoji.to_string(),
            context_analysis: context_analysis.clone(),
        })
    }

    // Deterministic threat scoring pipeline used when LLM is unavailable.
    fn generate_rule_based_assessment(
        &self,
        hits: &[Hit],
        device_addr: &str,
        mac_addr: &str,
        context_analysis: &ContextAnalysis,
    ) -> Certificate {
        let threat_weights: HashMap<&str, f32> = [
           ("credit_card", 85.0),
            ("ssn", 80.0),
            ("aadhaar_card", 80.0),
            ("pan_card", 70.0),
            ("email_sensitive", 60.0),
            ("phone_number", 60.0),
            ("password", 80.0),
        ].iter().cloned().collect();

        let threat_score = if hits.is_empty() {
            0.0
        } else {
              // Count violations by rule type
            let mut rule_counts: HashMap<&str, usize> = HashMap::new();
            for hit in hits {
                *rule_counts.entry(hit.rule.as_str()).or_insert(0) += 1;
            }
            
            // Calculate weighted sum: (count * weight) for each rule type
            let mut total_weighted_sum = 0.0;
            for (rule_type, count) in rule_counts {
                if let Some(weight) = threat_weights.get(rule_type) {
                    total_weighted_sum += (count as f32) * weight;
                } else {
                    total_weighted_sum += (count as f32) * 5.0; // Default weight
                }
            }
        
            // let avg_score: f32 = hits.iter()
            //     .map(|hit| {
            //         let base_weight = threat_weights.get(hit.rule.as_str()).unwrap_or(&5.0);
            //         // Adjust weight by context confidence
            //         base_weight * hit.context_confidence  * 12.5 
            //     })
            //     .sum::<f32>() / hits.len() as f32;
            
            // Apply count multiplier for consistency
               
        // let count_multiplier = match hits.len() {
        //     0 => 1.0,
        //     1 => 1.0,
        //     2..=3 => 1.1,
        //     4..=6 => 1.2,
        //     7..=10 => 1.3,  
        //     _ => 1.4,
        // };
                // let rule_counts: HashMap<&str, usize> = hits.iter()
            //     .fold(HashMap::new(), |mut acc, hit| {
            //         *acc.entry(hit.rule.as_str()).or_insert(0) += 1;
            //         acc
            //     });

            // let frequency_boost: f32 = rule_counts.values()
            //     .map(|&count| if count > 1 { (count - 1) as f32 * 2.0 } else { 0.0 })
            //     .sum();
              let avg_score = total_weighted_sum / (hits.len() as f32);
            // Context-based adjustment
            let context_multiplier = match context_analysis.primary_context.as_str() {
                "FINANCIAL" => 1.1,
                "BUSINESS" => 1.05,
                "TECHNICAL" => 1.0,
                _ => 1.0,
            };

            (avg_score * context_multiplier).min(100.0)
        };

        let threat_level = determine_threat_level(threat_score);
        let threat_level_clone = threat_level.clone();
        let (color_code, emoji) = get_threat_level_style(&threat_level_clone);

        let unique_rules: HashSet<String> = hits.iter()
            .map(|hit| hit.rule.clone())
            .collect();

        let rule_breakdown: HashMap<String, usize> = hits.iter()
            .fold(HashMap::new(), |mut acc, hit| {
                *acc.entry(hit.rule.clone()).or_insert(0) += 1;
                acc
            });

        Certificate {
            certificate_id: format!("THREAT_CERT_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S")),
            user_device: device_addr.to_string(),
            user_mac: mac_addr.to_string(),
            assessment_time: chrono::Utc::now().to_rfc3339(),
            assessment_method: "NLP-Enhanced Rule-based".to_string(),
            llm_available: self.llm_available,
            threat_score,
            threat_level,
            risk_analysis: get_context_aware_risk_analysis(&threat_level_clone, context_analysis),
            behavior_insights: get_enhanced_behavior_insights(hits, context_analysis),
            immediate_actions: get_context_aware_immediate_actions(&threat_level_clone, hits, context_analysis),
            training_recommendations: get_context_aware_training_recommendations(hits, context_analysis),
            total_violations: hits.len(),
            unique_rule_types: unique_rules.len(),
            rule_breakdown,
            color_code: color_code.to_string(),
            emoji: emoji.to_string(),
            context_analysis: context_analysis.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct LLMAssessment {
    threat_score: f32,
    threat_level: String,
    risk_analysis: String,
    behavior_insights: String,
    immediate_actions: Vec<String>,
    training_recommendations: Vec<String>,
}

// Extracts the first valid JSON object from an LLM text response.
fn extract_json_from_response(response: &str) -> Option<&str> {
    let start = response.find('{')?;
    let end = response.rfind('}')? + 1;
    Some(&response[start..end])
}

// Maps numeric threat score to discrete severity category.
fn determine_threat_level(score: f32) -> String {
    match score {
        s if s < 25.0 => "LOW_THREAT".to_string(),      // Changed from 30 to 25
        s if s < 55.0 => "MEDIUM_THREAT".to_string(),   // Changed from 60 to 55
        s if s < 85.0 => "HIGH_THREAT".to_string(),     // Changed from 85 to 85 (same)
        _ => "CRITICAL_THREAT".to_string(),
    }
}

// Returns color and symbol indicators for UI rendering.
// Remove emoji indicators.
fn get_threat_level_style(level: &str) -> (&str, &str) {
    match level {
        "NO_THREAT" => ("green", "🟢"),
        "LOW_THREAT" => ("blue", "🔵"),
        "MEDIUM_THREAT" => ("yellow", "🟡"),
        "HIGH_THREAT" => ("orange", "🟠"),
        "CRITICAL_THREAT" => ("red", "🔴"),
        _ => ("green", "🟢"),
    }
}

// Produces short risk explanation conditioned on context domain.
fn get_context_aware_risk_analysis(threat_level: &str, context: &ContextAnalysis) -> String {
    let base_analysis = match threat_level {
        "NO_THREAT" => "Normal user behavior with minimal security risks",
        "LOW_THREAT" => "Minor security lapses requiring basic awareness",
        "MEDIUM_THREAT" => "Moderate risk requiring intervention and training",
        "HIGH_THREAT" => "Significant security concerns requiring immediate action",
        "CRITICAL_THREAT" => "Critical security breach requiring emergency response",
        _ => "Risk assessment unavailable",
    };

    format!("{} in {} context", base_analysis, context.primary_context)
}

// Infers user behavior patterns based on violation mix and context type.
fn get_enhanced_behavior_insights(hits: &[Hit], context: &ContextAnalysis) -> String {
    if hits.is_empty() {
        return format!("User demonstrates good security hygiene in {} context", context.primary_context);
    }

    let rule_types: Vec<&str> = hits.iter().map(|hit| hit.rule.as_str()).collect();
    let context_str = &context.primary_context;
    
    if rule_types.contains(&"credit_card") && rule_types.contains(&"ssn") {
        format!("User handling multiple sensitive data types in {} context", context_str)
    } else if rule_types.contains(&"credit_card") {
        format!("Possible financial data exposure in {} context", context_str)
    } else if rule_types.contains(&"ssn") || rule_types.contains(&"aadhaar_card") {
        format!("Government ID data handling in {} context", context_str)
    } else {
        format!("Multiple security violations detected in {} context", context_str)
    }
}

// Produces action list influenced by threat level, rule types, and context domain.
fn get_context_aware_immediate_actions(threat_level: &str, hits: &[Hit], context: &ContextAnalysis) -> Vec<String> {
    let mut actions = Vec::new();
    
    match threat_level {
        "HIGH_THREAT" | "CRITICAL_THREAT" => {
            actions.extend_from_slice(&[
                format!("Immediate {} security review required", context.primary_context),
                "Consider temporary access restrictions".to_string(),
                "Notify security team immediately".to_string(),
            ]);
        }
        "MEDIUM_THREAT" => {
            actions.extend_from_slice(&[
                format!("Schedule {} security training", context.primary_context),
                "Review user access permissions".to_string(),
                "Implement enhanced monitoring".to_string(),
            ]);
        }
        "LOW_THREAT" => {
            actions.push(format!("Provide {} security awareness guidance", context.primary_context));
        }
        _ => {}
    }

    // Add context-specific actions
    if context.primary_context == "FINANCIAL" {
        actions.push("Enhanced financial data monitoring recommended".to_string());
    }

    let rule_types: Vec<&str> = hits.iter().map(|hit| hit.rule.as_str()).collect();
    if rule_types.contains(&"credit_card") {
        actions.push("Review PCI compliance procedures".to_string());
    }
    if rule_types.contains(&"ssn") || rule_types.contains(&"aadhaar_card") {
        actions.push("Audit sensitive data handling procedures".to_string());
    }

    if actions.is_empty() {
        vec!["Continue context-aware monitoring".to_string()]
    } else {
        actions
    }
}

// Maps violations and context to targeted training recommendations.
fn get_context_aware_training_recommendations(hits: &[Hit], context: &ContextAnalysis) -> Vec<String> {
    let mut trainings = Vec::new();
    let rule_types: Vec<&str> = hits.iter().map(|hit| hit.rule.as_str()).collect();
    
    // Context-specific trainings
    match context.primary_context.as_str() {
        "FINANCIAL" => {
            trainings.push("Financial data protection best practices".to_string());
        }
        "BUSINESS" => {
            trainings.push("Corporate data handling policies".to_string());
        }
        "TECHNICAL" => {
            trainings.push("Secure development practices".to_string());
        }
        _ => {}
    }

    // Rule-specific trainings
    if rule_types.contains(&"credit_card") {
        trainings.push("PCI compliance and sensitive data handling".to_string());
    }
    if rule_types.contains(&"ssn") || rule_types.contains(&"aadhaar_card") {
        trainings.push("Government ID data protection procedures".to_string());
    }
    if rule_types.contains(&"pan_card") {
        trainings.push("Tax identification data security".to_string());
    }
    if rule_types.contains(&"email_sensitive") {
        trainings.push("Data classification and sharing policies".to_string());
    }

    if trainings.is_empty() && !hits.is_empty() {
        vec![format!("General {} security awareness training", context.primary_context)]
    } else if trainings.is_empty() {
        vec!["Maintain current security awareness levels".to_string()]
    } else {
        trainings
    }
}