//! Call Graph Builder
//!
//! Builds interprocedural call graphs for cross-function analysis.
//! Enables detection of:
//! - Cross-function reentrancy
//! - State flow through call chains
//! - Call depth analysis

use thalir_core::{
    contract::Contract,
    function::Function,
    instructions::Instruction,
    block::BlockId,
};
use std::collections::{HashMap, HashSet, VecDeque};
use super::name_resolution::canonical_match;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FunctionCall {
    pub caller: String,
    pub callee: String,
    pub call_site_block: BlockId,
    pub call_site_index: usize,
    pub is_external: bool,
}

#[derive(Debug, Clone)]
pub struct CallGraph {
    pub callees: HashMap<String, Vec<FunctionCall>>,
    pub callers: HashMap<String, Vec<FunctionCall>>,
    pub functions: HashSet<String>,
}

impl CallGraph {
    pub fn new() -> Self {
        Self {
            callees: HashMap::new(),
            callers: HashMap::new(),
            functions: HashSet::new(),
        }
    }

    pub fn get_callees(&self, function: &str) -> Vec<&FunctionCall> {
        self.callees
            .get(function)
            .map(|calls| calls.iter().collect())
            .unwrap_or_default()
    }

    pub fn get_callers(&self, function: &str) -> Vec<&FunctionCall> {
        self.callers
            .get(function)
            .map(|calls| calls.iter().collect())
            .unwrap_or_default()
    }

    pub fn calls(&self, caller: &str, callee: &str) -> bool {
        self.callees
            .get(caller)
            .map(|calls| calls.iter().any(|c| c.callee == callee))
            .unwrap_or(false)
    }

    pub fn get_reachable_functions(&self, start: &str) -> HashSet<String> {
        let mut reachable = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start.to_string());

        while let Some(current) = queue.pop_front() {
            if reachable.contains(&current) {
                continue;
            }
            reachable.insert(current.clone());

            if let Some(callees) = self.callees.get(&current) {
                for call in callees {
                    if !call.is_external {
                        queue.push_back(call.callee.clone());
                    }
                }
            }
        }

        reachable
    }

    pub fn get_call_depth(&self, start: &str) -> HashMap<String, usize> {
        let mut depths = HashMap::new();
        let mut queue = VecDeque::new();
        queue.push_back((start.to_string(), 0));

        while let Some((current, depth)) = queue.pop_front() {
            if depths.contains_key(&current) {
                continue;
            }
            depths.insert(current.clone(), depth);

            if let Some(callees) = self.callees.get(&current) {
                for call in callees {
                    if !call.is_external {
                        queue.push_back((call.callee.clone(), depth + 1));
                    }
                }
            }
        }

        depths
    }

    pub fn find_call_paths(&self, start: &str, target: &str) -> Vec<Vec<String>> {
        let mut paths = Vec::new();
        let mut current_path = vec![start.to_string()];
        let mut visited = HashSet::new();

        self.dfs_paths(start, target, &mut current_path, &mut visited, &mut paths);

        paths
    }

    fn dfs_paths(
        &self,
        current: &str,
        target: &str,
        path: &mut Vec<String>,
        visited: &mut HashSet<String>,
        paths: &mut Vec<Vec<String>>,
    ) {
        if current == target {
            paths.push(path.clone());
            return;
        }

        visited.insert(current.to_string());

        if let Some(callees) = self.callees.get(current) {
            for call in callees {
                if !call.is_external && !visited.contains(&call.callee) {
                    path.push(call.callee.clone());
                    self.dfs_paths(&call.callee, target, path, visited, paths);
                    path.pop();
                }
            }
        }

        visited.remove(current);
    }

    pub fn has_external_call_in_path(&self, start: &str, end: &str) -> bool {
        let paths = self.find_call_paths(start, end);

        for path in paths {
            for i in 0..path.len() - 1 {
                let caller = &path[i];
                let callee = &path[i + 1];

                if let Some(calls) = self.callees.get(caller) {
                    for call in calls {
                        if call.callee == *callee && call.is_external {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }
}

impl Default for CallGraph {
    fn default() -> Self {
        Self::new()
    }
}

pub struct CallGraphBuilder {
    graph: CallGraph,
}

impl CallGraphBuilder {
    pub fn new() -> Self {
        Self {
            graph: CallGraph::new(),
        }
    }

    pub fn build(mut self, contract: &Contract) -> CallGraph {
        for (func_name, _) in &contract.functions {
            self.graph.functions.insert(func_name.clone());
        }

        for (func_name, function) in &contract.functions {
            self.analyze_function(func_name, function, contract);
        }

        self.graph
    }

    fn analyze_function(&mut self, func_name: &str, function: &Function, contract: &Contract) {
        for (block_id, block) in &function.body.blocks {
            for (idx, instruction) in block.instructions.iter().enumerate() {
                match instruction {
                    Instruction::Call { target, .. } => {
                        let (callee, is_external) = self.extract_call_target(target, contract);

                        let call = FunctionCall {
                            caller: func_name.to_string(),
                            callee: callee.clone(),
                            call_site_block: *block_id,
                            call_site_index: idx,
                            is_external,
                        };

                        self.graph
                            .callees
                            .entry(func_name.to_string())
                            .or_default()
                            .push(call.clone());

                        self.graph
                            .callers
                            .entry(callee)
                            .or_default()
                            .push(call);
                    }

                    Instruction::DelegateCall { target, .. } => {
                        let callee = format!("delegate:{:?}", target);

                        let call = FunctionCall {
                            caller: func_name.to_string(),
                            callee: callee.clone(),
                            call_site_block: *block_id,
                            call_site_index: idx,
                            is_external: true,
                        };

                        self.graph
                            .callees
                            .entry(func_name.to_string())
                            .or_default()
                            .push(call.clone());

                        self.graph
                            .callers
                            .entry(callee)
                            .or_default()
                            .push(call);
                    }

                    _ => {}
                }
            }
        }
    }

    fn extract_call_target(&self, target: &thalir_core::instructions::CallTarget, contract: &Contract) -> (String, bool) {
        match target {
            thalir_core::instructions::CallTarget::Internal(name) => {
                for func_name in contract.functions.keys() {
                    if canonical_match(name, func_name) {
                        return (func_name.clone(), false);
                    }
                }

                (name.clone(), true)
            }
            thalir_core::instructions::CallTarget::External(addr) => {
                (format!("external:{:?}", addr), true)
            }
            _ => ("unknown".to_string(), true),
        }
    }
}

impl Default for CallGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CallGraph {
    pub fn functions_with_external_calls(&self) -> HashSet<String> {
        let mut result = HashSet::new();

        for (func, calls) in &self.callees {
            if calls.iter().any(|c| c.is_external) {
                result.insert(func.clone());
            }
        }

        result
    }

    pub fn functions_reachable_from_external_calls(&self) -> HashMap<String, HashSet<String>> {
        let mut result = HashMap::new();

        for func in self.functions_with_external_calls() {
            let reachable = self.get_reachable_functions(&func);
            result.insert(func, reachable);
        }

        result
    }

    pub fn transitively_calls(&self, caller: &str, callee: &str) -> bool {
        let reachable = self.get_reachable_functions(caller);
        reachable.contains(callee)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_graph_creation() {
        let graph = CallGraph::new();
        assert!(graph.functions.is_empty());
        assert!(graph.callees.is_empty());
        assert!(graph.callers.is_empty());
    }

    #[test]
    fn test_reachable_functions() {
        let mut graph = CallGraph::new();

        graph.functions.insert("A".to_string());
        graph.functions.insert("B".to_string());
        graph.functions.insert("C".to_string());

        graph.callees.insert("A".to_string(), vec![
            FunctionCall {
                caller: "A".to_string(),
                callee: "B".to_string(),
                call_site_block: BlockId(0),
                call_site_index: 0,
                is_external: false,
            }
        ]);

        graph.callees.insert("B".to_string(), vec![
            FunctionCall {
                caller: "B".to_string(),
                callee: "C".to_string(),
                call_site_block: BlockId(0),
                call_site_index: 0,
                is_external: false,
            }
        ]);

        let reachable = graph.get_reachable_functions("A");
        assert!(reachable.contains("A"));
        assert!(reachable.contains("B"));
        assert!(reachable.contains("C"));
        assert_eq!(reachable.len(), 3);
    }
}
