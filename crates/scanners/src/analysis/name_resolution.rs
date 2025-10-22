//! Name Resolution for IR Function Calls
//!
//! Handles name mangling where IR call instructions use base names
//! (e.g., "_updateBalance") but the function map contains mangled names
//! with parameter types (e.g., "_updateBalance_address_uint256").


pub fn canonical_match(base: &str, candidate: &str) -> bool {
    if base.is_empty() {
        return false;
    }

    if base == candidate {
        return true;
    }

    if !candidate.starts_with(base) {
        return false;
    }

    let suffix = &candidate[base.len()..];


    if suffix.is_empty() {
        return true;
    }

    if !suffix.starts_with('_') {
        return false;
    }


    suffix.chars().all(|c| c.is_alphanumeric() || c == '_')
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_match_exact() {
        assert!(canonical_match("transfer", "transfer"));
        assert!(canonical_match("_updateBalance", "_updateBalance"));
    }

    #[test]
    fn test_canonical_match_with_types() {
        assert!(canonical_match("_updateBalance", "_updateBalance_address_uint256"));
        assert!(canonical_match("withdraw", "withdraw_uint256"));
        assert!(canonical_match("transfer", "transfer_address_uint256"));
        assert!(canonical_match("mint", "mint_address_uint256_bytes32"));
    }

    #[test]
    fn test_canonical_match_negative() {
        assert!(!canonical_match("withdraw", "deposit_uint256"));
        assert!(!canonical_match("_update", "_upgrade_address"));
        assert!(!canonical_match("transfer", "transferFrom_address_uint256"));
        assert!(!canonical_match("", "_updateBalance"));
    }

    #[test]
    fn test_canonical_match_edge_cases() {
        assert!(!canonical_match("transfer", "transferOwnership"));
        assert!(!canonical_match("mint", "mintTokens"));

        assert!(!canonical_match("test", "testfoo"));
    }

    #[test]
    fn test_canonical_match_common_types() {
        assert!(canonical_match("func", "func_address"));
        assert!(canonical_match("func", "func_uint256"));
        assert!(canonical_match("func", "func_uint8"));
        assert!(canonical_match("func", "func_bytes"));
        assert!(canonical_match("func", "func_bytes32"));
        assert!(canonical_match("func", "func_string"));
        assert!(canonical_match("func", "func_bool"));
    }

}
