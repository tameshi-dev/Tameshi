use serde::Serialize;

pub struct RawSolidityExtractor {
    source_code: String,
}

impl RawSolidityExtractor {
    pub fn new(source_code: String) -> Self {
        Self { source_code }
    }

    pub fn extract(&self) -> String {
        self.source_code
            .lines()
            .enumerate()
            .map(|(i, line)| format!("{:4} | {}", i + 1, line))
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn extract_plain(&self) -> String {
        self.source_code.clone()
    }

    pub fn extract_with_markers(&self) -> String {
        let mut result = Vec::new();

        for (i, line) in self.source_code.lines().enumerate() {
            let line_num = i + 1;
            let trimmed = line.trim();

            let marked_line = if trimmed.contains(".call{") || trimmed.contains(".call(")
                || trimmed.contains("msg.sender.call") || (trimmed.contains("address(") && trimmed.contains(".call")) {
                format!("{:4} | {} 🔴 // EXTERNAL CALL", line_num, line)
            } else if trimmed.starts_with("balances[") || trimmed.contains(" balances[") {
                if trimmed.contains("=") && !trimmed.contains("==") && !trimmed.contains(">=") && !trimmed.contains("<=") {
                    format!("{:4} | {} 🟡 // STATE WRITE", line_num, line)
                } else {
                    format!("{:4} | {}", line_num, line)
                }
            } else if trimmed.contains("storage") || trimmed.contains("mapping") {
                if trimmed.contains("=") && !trimmed.contains("==") {
                    format!("{:4} | {} 🟡 // STATE WRITE", line_num, line)
                } else {
                    format!("{:4} | {}", line_num, line)
                }
            } else if trimmed.starts_with("require(") || trimmed.starts_with("assert(") {
                format!("{:4} | {} ✅ // CHECK", line_num, line)
            } else if trimmed.contains("unchecked {") {
                format!("{:4} | {} ⚠️ // UNCHECKED BLOCK", line_num, line)
            } else {
                format!("{:4} | {}", line_num, line)
            };

            result.push(marked_line);
        }

        result.join("\n")
    }
}

#[derive(Serialize)]
pub struct SolidityAnalysisContext {
    pub source: String,
    pub format: String,
    pub instructions: String,
}

impl SolidityAnalysisContext {
    pub fn new_raw(source: String) -> Self {
        Self {
            source,
            format: "raw_solidity".to_string(),
            instructions: "Analyze the raw Solidity source code for vulnerabilities. Pay attention to line numbers for precise location reporting.".to_string(),
        }
    }

    pub fn new_marked(source: String) -> Self {
        Self {
            source,
            format: "marked_solidity".to_string(),
            instructions: "Analyze the Solidity source code with visual markers. 🔴 indicates external calls, 🟡 indicates state writes, ✅ indicates checks, ⚠️ indicates unchecked blocks.".to_string(),
        }
    }
}