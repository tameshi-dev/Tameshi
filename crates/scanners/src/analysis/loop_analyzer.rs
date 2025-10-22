//! Loop-Based Reentrancy Pattern Detection
//!
//! Detects reentrancy vulnerabilities where:
//! 1. External calls occur inside a loop
//! 2. State modifications occur after the loop completes
//!
//! Example vulnerable pattern:
//! ```solidity
//! for (uint i = 0; i < users.length; i++) {
//!     token.transfer(users[i], amounts[i]); // external call in loop
//! }
//! balances[msg.sender] = 0; // state update after loop - vulnerable!
//! ```

use thalir_core::{
    function::Function,
    instructions::Instruction,
    block::{BlockId, Terminator},
};
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct Loop {
    pub header: BlockId,
    pub body: HashSet<BlockId>,
    pub exits: HashSet<BlockId>,
}

#[derive(Debug, Clone)]
pub struct LoopReentrancyPattern {
    pub loop_info: Loop,
    pub calls_in_loop: Vec<(BlockId, usize)>, // (block, instruction_index)
    pub state_mods_after_loop: Vec<(BlockId, usize)>, // (block, instruction_index)
    pub modified_variables: Vec<String>,
}

pub struct LoopAnalyzer {
    loops: Vec<Loop>,
}

impl LoopAnalyzer {
    pub fn new() -> Self {
        Self {
            loops: Vec::new(),
        }
    }

    pub fn analyze_function(&mut self, function: &Function) -> Vec<Loop> {
        self.loops.clear();

        let back_edges = self.find_back_edges(function);

        for (tail, header) in back_edges {
            let body = self.find_loop_body(function, header, tail);
            let exits = self.find_loop_exits(function, &body);

            self.loops.push(Loop {
                header,
                body,
                exits,
            });
        }

        self.loops.clone()
    }

    fn find_back_edges(&self, function: &Function) -> Vec<(BlockId, BlockId)> {
        let mut back_edges = Vec::new();

        for (block_id, block) in &function.body.blocks {
            match &block.terminator {
                Terminator::Branch { then_block, else_block, .. } => {
                    if then_block <= block_id {
                        back_edges.push((*block_id, *then_block));
                    }
                    if else_block <= block_id {
                        back_edges.push((*block_id, *else_block));
                    }
                }
                Terminator::Jump(target, _) => {
                    if target <= block_id {
                        back_edges.push((*block_id, *target));
                    }
                }
                _ => {}
            }
        }

        back_edges
    }

    fn find_loop_body(&self, function: &Function, header: BlockId, tail: BlockId) -> HashSet<BlockId> {
        let mut body = HashSet::new();
        body.insert(header);

        let mut worklist = vec![tail];
        let mut visited = HashSet::new();

        while let Some(current) = worklist.pop() {
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current);

            if current != header {
                body.insert(current);

                for (pred_id, pred_block) in &function.body.blocks {
                    if self.is_predecessor(*pred_id, current, pred_block) {
                        worklist.push(*pred_id);
                    }
                }
            }
        }

        body
    }

    fn is_predecessor(&self, pred_id: BlockId, target: BlockId, pred_block: &thalir_core::block::BasicBlock) -> bool {
        match &pred_block.terminator {
            Terminator::Branch { then_block, else_block, .. } => {
                then_block == &target || else_block == &target
            }
            Terminator::Jump(jump_target, _) => {
                jump_target == &target
            }
            _ => false,
        }
    }

    fn find_loop_exits(&self, function: &Function, body: &HashSet<BlockId>) -> HashSet<BlockId> {
        let mut exits = HashSet::new();

        for block_id in body {
            if let Some(block) = function.body.blocks.get(block_id) {
                match &block.terminator {
                    Terminator::Branch { then_block, else_block, .. } => {
                        if !body.contains(then_block) {
                            exits.insert(*then_block);
                        }
                        if !body.contains(else_block) {
                            exits.insert(*else_block);
                        }
                    }
                    Terminator::Jump(target, _) => {
                        if !body.contains(target) {
                            exits.insert(*target);
                        }
                    }
                    _ => {}
                }
            }
        }

        exits
    }

    pub fn find_loop_reentrancy_patterns(&self, function: &Function) -> Vec<LoopReentrancyPattern> {
        let mut patterns = Vec::new();

        for loop_info in &self.loops {
            let mut calls_in_loop = Vec::new();

            for block_id in &loop_info.body {
                if let Some(block) = function.body.blocks.get(block_id) {
                    for (idx, instruction) in block.instructions.iter().enumerate() {
                        if Self::is_external_call(instruction) {
                            calls_in_loop.push((*block_id, idx));
                        }
                    }
                }
            }

            if calls_in_loop.is_empty() {
                continue;
            }

            let mut state_mods_after_loop = Vec::new();
            let mut modified_variables = Vec::new();

            let mut checked_blocks = HashSet::new();
            let mut to_check: Vec<_> = loop_info.exits.iter().copied().collect();

            while let Some(block_id) = to_check.pop() {
                if checked_blocks.contains(&block_id) {
                    continue;
                }
                checked_blocks.insert(block_id);

                if let Some(block) = function.body.blocks.get(&block_id) {
                    for (idx, instruction) in block.instructions.iter().enumerate() {
                        if Self::is_state_modification(instruction) {
                            state_mods_after_loop.push((block_id, idx));
                            modified_variables.push(Self::get_modified_variable(instruction));
                        }
                    }

                    if checked_blocks.len() < 10 {
                        match &block.terminator {
                            Terminator::Branch { then_block, else_block, .. } => {
                                to_check.push(*then_block);
                                to_check.push(*else_block);
                            }
                            Terminator::Jump(target, _) => {
                                to_check.push(*target);
                            }
                            _ => {}
                        }
                    }
                }
            }

            if !state_mods_after_loop.is_empty() {
                patterns.push(LoopReentrancyPattern {
                    loop_info: loop_info.clone(),
                    calls_in_loop,
                    state_mods_after_loop,
                    modified_variables,
                });
            }
        }

        patterns
    }

    fn is_external_call(inst: &Instruction) -> bool {
        match inst {
            Instruction::Call { target, .. } => {
                matches!(target, thalir_core::instructions::CallTarget::External(_))
            }
            Instruction::DelegateCall { .. } => true,
            _ => false,
        }
    }

    fn is_state_modification(inst: &Instruction) -> bool {
        matches!(inst,
            Instruction::StorageStore { .. } |
            Instruction::MappingStore { .. } |
            Instruction::ArrayStore { .. }
        )
    }

    fn get_modified_variable(inst: &Instruction) -> String {
        match inst {
            Instruction::StorageStore { key, .. } => format!("storage:{:?}", key),
            Instruction::MappingStore { key, .. } => format!("mapping:{:?}", key),
            Instruction::ArrayStore { index, .. } => format!("array:{:?}", index),
            _ => "unknown".to_string(),
        }
    }

    pub fn get_loops(&self) -> &[Loop] {
        &self.loops
    }
}

impl Default for LoopAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loop_analyzer_creation() {
        let analyzer = LoopAnalyzer::new();
        assert_eq!(analyzer.get_loops().len(), 0);
    }

}
