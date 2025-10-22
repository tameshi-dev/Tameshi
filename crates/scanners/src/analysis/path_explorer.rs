//! Path Explorer for Bounded CFG Path Analysis
//!
//! Explores multiple execution paths through the control flow graph
//! to detect reentrancy vulnerabilities across conditional branches.
//!
//! Example patterns detected:
//! ```solidity
//! if (condition1) {
//!     token.transfer(user, amount); // external call
//! }
//! // ... later in execution
//! balances[msg.sender] = 0; // state modification on any path
//! ```

use thalir_core::{
    function::Function,
    instructions::Instruction,
    block::{BlockId, Terminator},
};
use std::collections::{HashSet, VecDeque};

const MAX_PATH_LENGTH: usize = 20;

const MAX_PATHS: usize = 100;

#[derive(Debug, Clone)]
pub struct CFGPath {
    pub blocks: Vec<BlockId>,
    pub external_calls: Vec<(BlockId, usize)>, // (block, instruction_index)
    pub state_modifications: Vec<(BlockId, usize)>, // (block, instruction_index)
}

impl CFGPath {
    fn new(start: BlockId) -> Self {
        Self {
            blocks: vec![start],
            external_calls: Vec::new(),
            state_modifications: Vec::new(),
        }
    }

    fn extend(&self, next_block: BlockId) -> Self {
        let mut new_path = self.clone();
        new_path.blocks.push(next_block);
        new_path
    }

    fn length(&self) -> usize {
        self.blocks.len()
    }

    fn contains(&self, block: BlockId) -> bool {
        self.blocks.contains(&block)
    }
}

#[derive(Debug, Clone)]
pub struct ConditionalReentrancyPattern {
    pub call_path: CFGPath,
    pub state_mod_path: CFGPath,
    pub external_call: (BlockId, usize),
    pub state_modification: (BlockId, usize),
    pub divergence_point: Option<BlockId>,
    pub modified_variable: String,
}

pub struct PathExplorer {
    paths: Vec<CFGPath>,
}

impl PathExplorer {
    pub fn new() -> Self {
        Self {
            paths: Vec::new(),
        }
    }

    pub fn explore_function(&mut self, function: &Function) -> Vec<CFGPath> {
        self.paths.clear();

        let entry_block = self.find_entry_block(function);

        let mut queue = VecDeque::new();
        queue.push_back(CFGPath::new(entry_block));

        let mut paths_explored = 0;

        while let Some(current_path) = queue.pop_front() {
            if paths_explored >= MAX_PATHS {
                break;
            }
            paths_explored += 1;

            let current_block = *current_path.blocks.last().unwrap();

            if let Some(block) = function.body.blocks.get(&current_block) {
                let mut analyzed_path = current_path.clone();

                for (idx, instruction) in block.instructions.iter().enumerate() {
                    if Self::is_external_call(instruction) {
                        analyzed_path.external_calls.push((current_block, idx));
                    }
                    if Self::is_state_modification(instruction) {
                        analyzed_path.state_modifications.push((current_block, idx));
                    }
                }

                let successors = self.get_successors(&block.terminator);

                if successors.is_empty() {
                    self.paths.push(analyzed_path);
                } else {
                    for successor in successors {
                        if !analyzed_path.contains(successor) || analyzed_path.length() < 5 {
                            if analyzed_path.length() < MAX_PATH_LENGTH {
                                let new_path = analyzed_path.extend(successor);
                                queue.push_back(new_path);
                            } else {
                                self.paths.push(analyzed_path.clone());
                            }
                        }
                    }
                }
            }
        }

        self.paths.clone()
    }

    fn find_entry_block(&self, function: &Function) -> BlockId {
        function.body.blocks.keys()
            .min()
            .copied()
            .unwrap_or(BlockId(0))
    }

    fn get_successors(&self, terminator: &Terminator) -> Vec<BlockId> {
        match terminator {
            Terminator::Branch { then_block, else_block, .. } => {
                vec![*then_block, *else_block]
            }
            Terminator::Jump(target, _) => {
                vec![*target]
            }
            Terminator::Switch { default, cases, .. } => {
                let mut successors = vec![*default];
                successors.extend(cases.iter().map(|(_, target)| *target));
                successors
            }
            Terminator::Return(_) | Terminator::Revert(_) | Terminator::Panic(_) | Terminator::Invalid => {
                vec![] // No successors - function exits
            }
        }
    }

    pub fn find_conditional_reentrancy(&self) -> Vec<ConditionalReentrancyPattern> {
        let mut patterns = Vec::new();

        let call_paths: Vec<_> = self.paths.iter()
            .filter(|p| !p.external_calls.is_empty())
            .collect();

        let state_mod_paths: Vec<_> = self.paths.iter()
            .filter(|p| !p.state_modifications.is_empty())
            .collect();

        for call_path in &call_paths {
            for state_mod_path in &state_mod_paths {
                for &external_call in &call_path.external_calls {
                    for &state_modification in &state_mod_path.state_modifications {
                        if self.is_valid_reentrancy_pattern(
                            call_path,
                            state_mod_path,
                            external_call,
                            state_modification,
                        ) {
                            let divergence = self.find_divergence_point(call_path, state_mod_path);

                            patterns.push(ConditionalReentrancyPattern {
                                call_path: (*call_path).clone(),
                                state_mod_path: (*state_mod_path).clone(),
                                external_call,
                                state_modification,
                                divergence_point: divergence,
                                modified_variable: format!("state_{:?}", state_modification),
                            });
                        }
                    }
                }
            }
        }

        self.deduplicate_patterns(patterns)
    }

    fn is_valid_reentrancy_pattern(
        &self,
        call_path: &CFGPath,
        state_mod_path: &CFGPath,
        external_call: (BlockId, usize),
        state_modification: (BlockId, usize),
    ) -> bool {
        let (call_block, call_idx) = external_call;
        let (mod_block, mod_idx) = state_modification;

        if call_path.blocks == state_mod_path.blocks {
            let call_pos = call_path.blocks.iter().position(|&b| b == call_block);
            let mod_pos = state_mod_path.blocks.iter().position(|&b| b == mod_block);

            match (call_pos, mod_pos) {
                (Some(cp), Some(mp)) => {
                    if cp < mp {
                        return true; // Different blocks, mod after call
                    } else if cp == mp {
                        return mod_idx > call_idx; // Same block, check instruction order
                    }
                }
                _ => {}
            }
        }

        if self.paths_could_be_sequential(call_path, state_mod_path) {
            return true;
        }

        false
    }

    fn paths_could_be_sequential(&self, path1: &CFGPath, path2: &CFGPath) -> bool {
        let path1_blocks: HashSet<_> = path1.blocks.iter().collect();
        let path2_blocks: HashSet<_> = path2.blocks.iter().collect();

        path1_blocks.intersection(&path2_blocks).count() > 0
    }

    fn find_divergence_point(&self, path1: &CFGPath, path2: &CFGPath) -> Option<BlockId> {
        let min_len = path1.blocks.len().min(path2.blocks.len());

        for i in 0..min_len {
            if path1.blocks[i] != path2.blocks[i] {
                if i > 0 {
                    return Some(path1.blocks[i - 1]);
                } else {
                    return None; // Diverge immediately
                }
            }
        }

        if path1.blocks.len() != path2.blocks.len() {
            Some(path1.blocks[min_len - 1])
        } else {
            None // Paths are identical
        }
    }

    fn deduplicate_patterns(&self, patterns: Vec<ConditionalReentrancyPattern>) -> Vec<ConditionalReentrancyPattern> {
        let mut seen = HashSet::new();
        let mut unique = Vec::new();

        for pattern in patterns {
            let key = (pattern.external_call, pattern.state_modification);
            if !seen.contains(&key) {
                seen.insert(key);
                unique.push(pattern);
            }
        }

        unique
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

    pub fn get_paths(&self) -> &[CFGPath] {
        &self.paths
    }
}

impl Default for PathExplorer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_explorer_creation() {
        let explorer = PathExplorer::new();
        assert_eq!(explorer.get_paths().len(), 0);
    }

    #[test]
    fn test_cfg_path_creation() {
        let path = CFGPath::new(BlockId(0));
        assert_eq!(path.blocks.len(), 1);
        assert_eq!(path.blocks[0], BlockId(0));
        assert!(path.external_calls.is_empty());
        assert!(path.state_modifications.is_empty());
    }

    #[test]
    fn test_cfg_path_extension() {
        let path = CFGPath::new(BlockId(0));
        let extended = path.extend(BlockId(1));
        assert_eq!(extended.blocks.len(), 2);
        assert_eq!(extended.blocks[0], BlockId(0));
        assert_eq!(extended.blocks[1], BlockId(1));
    }

    #[test]
    fn test_path_contains() {
        let path = CFGPath::new(BlockId(0)).extend(BlockId(1));
        assert!(path.contains(BlockId(0)));
        assert!(path.contains(BlockId(1)));
        assert!(!path.contains(BlockId(2)));
    }
}
