//! Shared utilities for source location provenance tracking
//!
//! This module provides common functionality for extracting source locations
//! and snippets from IR instructions across all scanners.

use crate::core::Location;
use thalir_core::Contract;

pub fn get_instruction_location(
    contract: &Contract,
    func_name: &str,
    block_id: thalir_core::block::BlockId,
    instruction_index: usize,
) -> Location {
    if let Some(function) = contract.functions.get(func_name) {
        if let Some(block) = function.body.blocks.get(&block_id) {
            if let Some(source_loc) = block.metadata.get_location(instruction_index) {
                let snippet = if let Some(ref source_code) = contract.metadata.source_code {
                    source_loc.extract_snippet(source_code)
                } else {
                    None
                };

                return Location {
                    file: source_loc.file.clone(),
                    line: source_loc.line as usize,
                    column: source_loc.column as usize,
                    end_line: source_loc.end_line.map(|l| l as usize),
                    end_column: source_loc.end_column.map(|c| c as usize),
                    snippet,
                    ir_position: Some(crate::core::IRPosition {
                        function: func_name.to_string(),
                        position: instruction_index,
                        block_id: block_id.0 as usize,
                        operation: None,
                    }),
                };
            }
        }
    }

    Location {
        file: contract
            .metadata
            .source_file
            .clone()
            .unwrap_or_else(|| format!("{}.sol", contract.name)),
        line: instruction_index,
        column: 0,
        end_line: None,
        end_column: None,
        snippet: None,
        ir_position: Some(crate::core::IRPosition {
            function: func_name.to_string(),
            position: instruction_index,
            block_id: block_id.0 as usize,
            operation: None,
        }),
    }
}
