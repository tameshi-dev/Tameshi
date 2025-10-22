//! Hook and Callback Recognition for Reentrancy Analysis
//!
//! Identifies external calls that trigger callbacks (hooks) which can be
//! exploited as reentrancy vectors. Supports:
//! - ERC777 token transfers (tokensReceived, tokensToSend)
//! - ERC721 NFT transfers (onERC721Received)
//! - ERC1155 token transfers (onERC1155Received, onERC1155BatchReceived)

use thalir_core::instructions::{Instruction, CallTarget};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CallbackType {
    ERC777TokensReceived,
    ERC777TokensToSend,
    ERC721Received,
    ERC1155Received,
    ERC1155BatchReceived,
}

impl CallbackType {
    pub fn function_name(&self) -> &'static str {
        match self {
            CallbackType::ERC777TokensReceived => "tokensReceived",
            CallbackType::ERC777TokensToSend => "tokensToSend",
            CallbackType::ERC721Received => "onERC721Received",
            CallbackType::ERC1155Received => "onERC1155Received",
            CallbackType::ERC1155BatchReceived => "onERC1155BatchReceived",
        }
    }

    pub fn all_names() -> HashSet<&'static str> {
        vec![
            "tokensReceived",
            "tokensToSend",
            "onERC721Received",
            "onERC1155Received",
            "onERC1155BatchReceived",
        ].into_iter().collect()
    }
}

#[derive(Debug, Clone)]
pub struct CallbackTrigger {
    pub interface: String,
    pub function: String,
    pub callback_type: CallbackType,
}

impl CallbackTrigger {
    pub fn new(interface: impl Into<String>, function: impl Into<String>, callback_type: CallbackType) -> Self {
        Self {
            interface: interface.into(),
            function: function.into(),
            callback_type,
        }
    }

    pub fn known_triggers() -> Vec<CallbackTrigger> {
        vec![
            CallbackTrigger::new("IERC777", "send", CallbackType::ERC777TokensReceived),
            CallbackTrigger::new("IERC777", "operatorSend", CallbackType::ERC777TokensReceived),
            CallbackTrigger::new("IERC777", "burn", CallbackType::ERC777TokensToSend),
            CallbackTrigger::new("IERC777", "operatorBurn", CallbackType::ERC777TokensToSend),

            CallbackTrigger::new("IERC721", "safeTransferFrom", CallbackType::ERC721Received),

            CallbackTrigger::new("IERC1155", "safeTransferFrom", CallbackType::ERC1155Received),
            CallbackTrigger::new("IERC1155", "safeBatchTransferFrom", CallbackType::ERC1155BatchReceived),
        ]
    }
}

pub struct HookAnalyzer {
    callback_names: HashSet<&'static str>,
    triggers: Vec<CallbackTrigger>,
}

impl HookAnalyzer {
    pub fn new() -> Self {
        Self {
            callback_names: CallbackType::all_names(),
            triggers: CallbackTrigger::known_triggers(),
        }
    }

    pub fn is_callback_function(&self, func_name: &str) -> bool {
        if self.callback_names.contains(func_name) {
            return true;
        }

        for callback_name in &self.callback_names {
            if func_name.starts_with(callback_name) {
                return true;
            }
        }

        false
    }

    pub fn get_callback_type(&self, func_name: &str) -> Option<CallbackType> {
        if func_name.starts_with("tokensReceived") {
            Some(CallbackType::ERC777TokensReceived)
        } else if func_name.starts_with("tokensToSend") {
            Some(CallbackType::ERC777TokensToSend)
        } else if func_name.starts_with("onERC721Received") {
            Some(CallbackType::ERC721Received)
        } else if func_name.starts_with("onERC1155Received") && !func_name.contains("Batch") {
            Some(CallbackType::ERC1155Received)
        } else if func_name.starts_with("onERC1155BatchReceived") {
            Some(CallbackType::ERC1155BatchReceived)
        } else {
            None
        }
    }

    pub fn may_trigger_callback(&self, instruction: &Instruction) -> Option<CallbackType> {
        match instruction {
            Instruction::Call { target, .. } => {
                let target_str = format!("{:?}", target);

                for trigger in &self.triggers {
                    if target_str.contains(&trigger.function) {
                        return Some(trigger.callback_type.clone());
                    }
                }

                if target_str.contains("transfer") && !target_str.contains("transferFrom") {
                    return Some(CallbackType::ERC777TokensReceived);
                }

                None
            }
            _ => None,
        }
    }

    pub fn is_callback_trigger_target(&self, target: &CallTarget) -> bool {
        match target {
            CallTarget::External(_) => {
                let target_str = format!("{:?}", target);

                for trigger in &self.triggers {
                    if target_str.contains(&trigger.function) {
                        return true;
                    }
                }

                target_str.contains("transfer") ||
                target_str.contains("send") ||
                target_str.contains("mint") ||
                target_str.contains("burn")
            }
            _ => false,
        }
    }
}

impl Default for HookAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

pub fn is_erc777_hook(function_name: &str) -> bool {
    function_name.starts_with("tokensReceived") ||
    function_name.starts_with("tokensToSend")
}

pub fn is_nft_hook(function_name: &str) -> bool {
    function_name.starts_with("onERC721Received") ||
    function_name.starts_with("onERC1155Received") ||
    function_name.starts_with("onERC1155BatchReceived")
}

pub fn is_callback_hook(function_name: &str) -> bool {
    is_erc777_hook(function_name) || is_nft_hook(function_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_callback_type_function_names() {
        assert_eq!(CallbackType::ERC777TokensReceived.function_name(), "tokensReceived");
        assert_eq!(CallbackType::ERC721Received.function_name(), "onERC721Received");
    }

    #[test]
    fn test_is_callback_function() {
        let analyzer = HookAnalyzer::new();

        assert!(analyzer.is_callback_function("tokensReceived"));
        assert!(analyzer.is_callback_function("onERC721Received"));
        assert!(analyzer.is_callback_function("onERC1155Received"));

        assert!(analyzer.is_callback_function("tokensReceived_address_address_uint256_bytes_bytes"));
        assert!(analyzer.is_callback_function("onERC721Received_address_address_uint256_bytes"));

        assert!(!analyzer.is_callback_function("transfer"));
        assert!(!analyzer.is_callback_function("withdraw"));
    }

    #[test]
    fn test_get_callback_type() {
        let analyzer = HookAnalyzer::new();

        assert_eq!(
            analyzer.get_callback_type("tokensReceived"),
            Some(CallbackType::ERC777TokensReceived)
        );

        assert_eq!(
            analyzer.get_callback_type("onERC721Received_address_address_uint256_bytes"),
            Some(CallbackType::ERC721Received)
        );

        assert_eq!(analyzer.get_callback_type("withdraw"), None);
    }

    #[test]
    fn test_is_erc777_hook() {
        assert!(is_erc777_hook("tokensReceived"));
        assert!(is_erc777_hook("tokensToSend"));
        assert!(is_erc777_hook("tokensReceived_address_address_uint256_bytes_bytes"));
        assert!(!is_erc777_hook("transfer"));
    }

    #[test]
    fn test_is_nft_hook() {
        assert!(is_nft_hook("onERC721Received"));
        assert!(is_nft_hook("onERC1155Received"));
        assert!(is_nft_hook("onERC1155BatchReceived"));
        assert!(!is_nft_hook("tokensReceived"));
    }

    #[test]
    fn test_is_callback_hook() {
        assert!(is_callback_hook("tokensReceived"));
        assert!(is_callback_hook("onERC721Received"));
        assert!(is_callback_hook("onERC1155Received"));
        assert!(!is_callback_hook("transfer"));
        assert!(!is_callback_hook("withdraw"));
    }
}
