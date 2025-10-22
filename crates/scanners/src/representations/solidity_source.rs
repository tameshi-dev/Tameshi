use super::traits::Representation;
use std::any::Any;

#[derive(Debug, Clone)]
pub struct SoliditySource {
    pub content: String,
    pub file_path: Option<String>,
    pub pragma_version: Option<String>,
    pub contract_names: Vec<String>,
}

impl SoliditySource {
    pub fn new(content: String) -> Self {
        let contract_names = Self::extract_contract_names(&content);
        let pragma_version = Self::extract_pragma(&content);

        Self {
            content,
            file_path: None,
            pragma_version,
            contract_names,
        }
    }

    pub fn with_file_path(mut self, path: String) -> Self {
        self.file_path = Some(path);
        self
    }

    fn extract_contract_names(content: &str) -> Vec<String> {
        let mut names = Vec::new();
        for line in content.lines() {
            if let Some(start) = line.find("contract ") {
                let after_contract = &line[start + 9..];
                if let Some(end) = after_contract.find(|c: char| c == ' ' || c == '{') {
                    names.push(after_contract[..end].to_string());
                }
            } else if let Some(start) = line.find("interface ") {
                let after_interface = &line[start + 10..];
                if let Some(end) = after_interface.find(|c: char| c == ' ' || c == '{') {
                    names.push(after_interface[..end].to_string());
                }
            } else if let Some(start) = line.find("library ") {
                let after_library = &line[start + 8..];
                if let Some(end) = after_library.find(|c: char| c == ' ' || c == '{') {
                    names.push(after_library[..end].to_string());
                }
            }
        }
        names
    }

    fn extract_pragma(content: &str) -> Option<String> {
        for line in content.lines() {
            if line.trim().starts_with("pragma solidity") {
                return Some(line.trim().to_string());
            }
        }
        None
    }

    pub fn get_function(&self, name: &str) -> Option<String> {
        let lines: Vec<&str> = self.content.lines().collect();
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
            None
        } else {
            Some(result.join("\n"))
        }
    }

    pub fn line_count(&self) -> usize {
        self.content.lines().count()
    }

    pub fn contains_pattern(&self, pattern: &str) -> bool {
        self.content.contains(pattern)
    }
}

impl Representation for SoliditySource {
    type Id = String; // Use file path or contract name as ID

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
