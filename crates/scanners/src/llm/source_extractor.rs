use crate::core::context::AnalysisContext;
use crate::llm::representation::{
    Focus, RepresentationExtractor, RepresentationSnippet, SnippetMetadata, SnippetStrategy,
    VulnerabilityPattern,
};
use anyhow::Result;
use std::fmt::Debug;

#[derive(Debug, Clone)]
pub struct SoliditySourceExtractor {
    strategy: SnippetStrategy,
    include_comments: bool,
    max_lines: usize,
}

impl Default for SoliditySourceExtractor {
    fn default() -> Self {
        Self {
            strategy: SnippetStrategy::FullContract,
            include_comments: false,
            max_lines: 1000,
        }
    }
}

impl SoliditySourceExtractor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_strategy(mut self, strategy: SnippetStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    pub fn with_comments(mut self, include: bool) -> Self {
        self.include_comments = include;
        self
    }

    pub fn with_max_lines(mut self, max: usize) -> Self {
        self.max_lines = max;
        self
    }

    fn extract_source_code(&self, context: &AnalysisContext) -> Result<String> {
        match context.get_representation::<crate::representations::SoliditySource>() {
            Ok(source) => Ok(source.content.clone()),
            Err(_) => {
                Ok("// Solidity source code not found in context. Add SoliditySource to RepresentationBundle.".to_string())
            }
        }
    }

    fn focus_on_pattern(&self, source: &str, pattern: &VulnerabilityPattern) -> String {
        match pattern {
            VulnerabilityPattern::ExternalCalls => self.extract_external_calls(source),
            VulnerabilityPattern::Initialization => self.extract_state_changes(source),
            VulnerabilityPattern::AccessControl => self.extract_access_control(source),
            VulnerabilityPattern::MoneyFlow => self.extract_money_flow(source),
            _ => source.to_string(),
        }
    }

    fn extract_external_calls(&self, source: &str) -> String {
        let mut result = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            if line.contains(".call")
                || line.contains(".delegatecall")
                || line.contains(".transfer")
                || line.contains(".send")
                || line.contains("msg.sender.call")
            {
                let start = i.saturating_sub(3);
                let end = (i + 4).min(lines.len());

                result.push(format!("// Lines {}-{}", start + 1, end));
                for j in start..end {
                    result.push(lines[j].to_string());
                }
                result.push("".to_string());
            }
        }

        if result.is_empty() {
            "// No external calls found".to_string()
        } else {
            result.join("\n")
        }
    }

    fn extract_state_changes(&self, source: &str) -> String {
        let mut result = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            if (line.contains(" = ")
                || line.contains(" += ")
                || line.contains(" -= ")
                || line.contains(" *= "))
                && !line.trim().starts_with("//")
            {
                if !line.contains("memory")
                    && !line.contains("let ")
                    && !line.contains("var ")
                    && !line.contains("uint256 ")
                    && !line.contains("address ")
                    && !line.contains("bool ")
                {
                    let start = i.saturating_sub(1);
                    let end = (i + 2).min(lines.len());

                    result.push(format!("// Line {}", i + 1));
                    for j in start..end {
                        result.push(lines[j].to_string());
                    }
                    result.push("".to_string());
                }
            }
        }

        if result.is_empty() {
            "// No state changes found".to_string()
        } else {
            result.join("\n")
        }
    }

    fn extract_access_control(&self, source: &str) -> String {
        let mut result = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            if line.contains("onlyOwner")
                || line.contains("require(msg.sender")
                || line.contains("require(owner")
                || line.contains("modifier ")
                || line.contains("public")
                || line.contains("external")
                || line.contains("private")
                || line.contains("internal")
            {
                result.push(format!("// Line {}", i + 1));
                result.push(lines[i].to_string());
            }
        }

        if result.is_empty() {
            "// No access control patterns found".to_string()
        } else {
            result.join("\n")
        }
    }

    fn extract_money_flow(&self, source: &str) -> String {
        let mut result = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            if line.contains("msg.value")
                || line.contains(".transfer")
                || line.contains(".send")
                || line.contains("payable")
                || line.contains("withdraw")
                || line.contains("deposit")
                || line.contains("balance")
            {
                let start = i.saturating_sub(2);
                let end = (i + 3).min(lines.len());

                result.push(format!("// Lines {}-{}", start + 1, end));
                for j in start..end {
                    result.push(lines[j].to_string());
                }
                result.push("".to_string());
            }
        }

        if result.is_empty() {
            "// No money flow patterns found".to_string()
        } else {
            result.join("\n")
        }
    }

    fn remove_comments(&self, source: &str) -> String {
        let mut result = Vec::new();
        let mut in_multiline = false;

        for line in source.lines() {
            let mut clean_line = String::new();
            let mut chars = line.chars().peekable();

            while let Some(ch) = chars.next() {
                if in_multiline {
                    if ch == '*' && chars.peek() == Some(&'/') {
                        chars.next(); // consume '/'
                        in_multiline = false;
                    }
                } else if ch == '/' {
                    if chars.peek() == Some(&'/') {
                        break;
                    } else if chars.peek() == Some(&'*') {
                        chars.next(); // consume '*'
                        in_multiline = true;
                    } else {
                        clean_line.push(ch);
                    }
                } else {
                    clean_line.push(ch);
                }
            }

            let trimmed = clean_line.trim();
            if !trimmed.is_empty() {
                result.push(clean_line);
            }
        }

        result.join("\n")
    }
}

impl RepresentationExtractor for SoliditySourceExtractor {
    fn extract(&self, context: &AnalysisContext) -> Result<RepresentationSnippet> {
        let source = self.extract_source_code(context)?;

        let processed = if self.include_comments {
            source
        } else {
            self.remove_comments(&source)
        };

        let snippet = match self.strategy {
            SnippetStrategy::FullContract => processed,
            SnippetStrategy::FunctionLevel => {
                let lines: Vec<&str> = processed.lines().collect();
                let mut result = Vec::new();
                let mut in_function = false;
                let mut brace_count = 0;

                for line in lines {
                    if line.contains("function ") {
                        in_function = true;
                        brace_count = 0;
                    }

                    if in_function {
                        result.push(line.to_string());
                        brace_count += line.chars().filter(|&c| c == '{').count() as i32;
                        brace_count -= line.chars().filter(|&c| c == '}').count() as i32;

                        if brace_count <= 0 && line.contains('}') {
                            in_function = false;
                            result.push("".to_string());
                        }
                    }
                }

                result.join("\n")
            }
            _ => processed,
        };

        let token_count = self.estimate_tokens(&snippet);

        Ok(RepresentationSnippet {
            content: snippet.clone(),
            metadata: SnippetMetadata {
                representation_type: "solidity_source".to_string(),
                extraction_strategy: format!("{:?}", self.strategy),
                source_location: None,
                included_functions: vec![],
                included_contracts: vec![],
                was_truncated: false,
            },
            token_count,
        })
    }

    fn extract_focused(
        &self,
        context: &AnalysisContext,
        focus: &Focus,
    ) -> Result<RepresentationSnippet> {
        let source = self.extract_source_code(context)?;

        let processed = if self.include_comments {
            source
        } else {
            self.remove_comments(&source)
        };

        let focused = match focus {
            Focus::Pattern(pattern) => self.focus_on_pattern(&processed, pattern),
            Focus::Function(name) => {
                let lines: Vec<&str> = processed.lines().collect();
                let mut result = Vec::new();
                let mut found = false;
                let mut brace_count = 0;

                for line in lines {
                    if line.contains(&format!("function {}", name)) {
                        found = true;
                        brace_count = 0;
                    }

                    if found {
                        result.push(line.to_string());
                        brace_count += line.chars().filter(|&c| c == '{').count() as i32;
                        brace_count -= line.chars().filter(|&c| c == '}').count() as i32;

                        if brace_count <= 0 && line.contains('}') {
                            break;
                        }
                    }
                }

                if result.is_empty() {
                    format!("// Function '{}' not found", name)
                } else {
                    result.join("\n")
                }
            }
            Focus::Contract(name) => {
                let lines: Vec<&str> = processed.lines().collect();
                let mut result = Vec::new();
                let mut found = false;
                let mut brace_count = 0;

                for line in lines {
                    if line.contains(&format!("contract {}", name)) {
                        found = true;
                        brace_count = 0;
                    }

                    if found {
                        result.push(line.to_string());
                        brace_count += line.chars().filter(|&c| c == '{').count() as i32;
                        brace_count -= line.chars().filter(|&c| c == '}').count() as i32;

                        if brace_count <= 0 && line.contains('}') {
                            break;
                        }
                    }
                }

                if result.is_empty() {
                    format!("// Contract '{}' not found", name)
                } else {
                    result.join("\n")
                }
            }
            Focus::Region(_) => {
                processed.clone()
            }
            Focus::Multiple(_) => {
                processed.clone()
            }
        };

        let token_count = self.estimate_tokens(&focused);

        Ok(RepresentationSnippet {
            content: focused.clone(),
            metadata: SnippetMetadata {
                representation_type: "solidity_source".to_string(),
                extraction_strategy: format!("focused_{:?}", focus),
                source_location: None,
                included_functions: vec![],
                included_contracts: vec![],
                was_truncated: false,
            },
            token_count,
        })
    }

    fn representation_type(&self) -> &str {
        "solidity_source"
    }
}
