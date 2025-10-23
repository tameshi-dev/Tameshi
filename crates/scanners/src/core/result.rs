use crate::core::{Confidence, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Location {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub end_line: Option<usize>,
    pub end_column: Option<usize>,
    pub snippet: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub ir_position: Option<IRPosition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct IRPosition {
    pub function: String,

    pub position: usize,

    pub block_id: usize,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
}

impl Location {
    pub fn new(file: String, line: usize, column: usize) -> Self {
        Self {
            file,
            line,
            column,
            end_line: None,
            end_column: None,
            snippet: None,
            ir_position: None,
        }
    }

    pub fn with_ir_position(mut self, function: String, position: usize, block_id: usize) -> Self {
        self.ir_position = Some(IRPosition {
            function,
            position,
            block_id,
            operation: None,
        });
        self
    }

    pub fn with_operation(mut self, operation: String) -> Self {
        if let Some(ref mut ir_pos) = self.ir_position {
            ir_pos.operation = Some(operation);
        }
        self
    }

    pub fn with_end(mut self, end_line: usize, end_column: usize) -> Self {
        self.end_line = Some(end_line);
        self.end_column = Some(end_column);
        self
    }

    pub fn with_snippet(mut self, snippet: String) -> Self {
        self.snippet = Some(snippet);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub scanner_id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub swc_id: Option<String>,

    pub finding_type: String,

    pub severity: Severity,

    pub base_severity: Severity,

    pub confidence: Confidence,

    pub confidence_score: f64,

    pub title: String,

    pub description: String,

    pub locations: Vec<Location>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<FindingMetadata>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity_context: Option<SeverityContext>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<crate::core::provenance::FindingProvenance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityContext {
    pub escalation_factors: Vec<String>,

    pub mitigation_factors: Vec<String>,

    pub holds_value: bool,

    pub is_public: bool,

    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub custom_factors: HashMap<String, String>,
}

impl Finding {
    pub fn new(
        scanner_id: String,
        severity: Severity,
        confidence: Confidence,
        title: String,
        description: String,
    ) -> Self {
        Self {
            scanner_id: scanner_id.clone(),
            swc_id: None,
            finding_type: scanner_id, // Default to scanner_id
            severity,
            base_severity: severity,
            confidence,
            confidence_score: confidence.to_score(),
            title,
            description,
            locations: Vec::new(),
            metadata: None,
            severity_context: None,
            provenance: None,
        }
    }

    pub fn with_location(mut self, location: Location) -> Self {
        self.locations.push(location);
        self
    }

    pub fn with_locations(mut self, locations: Vec<Location>) -> Self {
        self.locations = locations;
        self
    }

    pub fn with_metadata(mut self, metadata: FindingMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    pub fn with_swc_id(mut self, swc_id: String) -> Self {
        self.swc_id = Some(swc_id);
        self
    }

    pub fn with_finding_type(mut self, finding_type: String) -> Self {
        self.finding_type = finding_type;
        self
    }

    pub fn with_confidence_score(mut self, confidence: Confidence, score: f64) -> Self {
        self.confidence = confidence;
        self.confidence_score = score;
        self
    }

    pub fn with_location_parts(mut self, file: &str, line: u32, column: u32) -> Self {
        self.locations.push(Location::new(
            file.to_string(),
            line as usize,
            column as usize,
        ));
        self
    }

    pub fn with_contract(mut self, contract: &str) -> Self {
        if self.metadata.is_none() {
            self.metadata = Some(FindingMetadata::default());
        }
        if let Some(ref mut meta) = self.metadata {
            meta.affected_contracts.push(contract.to_string());
        }
        self
    }

    pub fn with_function(mut self, function: &str) -> Self {
        if self.metadata.is_none() {
            self.metadata = Some(FindingMetadata::default());
        }
        if let Some(ref mut meta) = self.metadata {
            meta.affected_functions.push(function.to_string());
        }
        self
    }

    pub fn with_severity_context(mut self, context: SeverityContext) -> Self {
        self.severity_context = Some(context);
        self
    }

    pub fn with_provenance(mut self, provenance: crate::core::provenance::FindingProvenance) -> Self {
        self.provenance = Some(provenance);
        self
    }

    pub fn adjust_severity(mut self, new_severity: Severity) -> Self {
        self.severity = new_severity;
        self
    }

    pub fn priority_score(&self) -> u32 {
        let severity_score = match self.severity {
            Severity::Critical => 1000,
            Severity::High => 100,
            Severity::Medium => 10,
            Severity::Low => 1,
            Severity::Informational => 0,
        };

        let confidence_multiplier = match self.confidence {
            Confidence::High => 10,
            Confidence::Medium => 5,
            Confidence::Low => 1,
        };

        severity_score * confidence_multiplier
    }

    pub fn dedup_key(&self) -> String {
        let mut key = format!("{}:{}", self.finding_type, self.scanner_id);

        if let Some(loc) = self.locations.first() {
            key.push_str(&format!(":{}:{}:{}", loc.file, loc.line, loc.column));
        }

        key
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FindingMetadata {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub affected_functions: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub affected_variables: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub affected_contracts: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_impact: Option<GasImpact>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub representation_info: Option<RepresentationInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepresentationInfo {
    pub representation_type: String,
    pub extraction_strategy: String,
    pub token_count: usize,
    pub was_truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub included_functions: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub included_contracts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasImpact {
    pub min_gas: u64,
    pub max_gas: u64,
    pub average_gas: u64,
}
