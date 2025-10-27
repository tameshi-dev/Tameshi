/// Test for UncheckedArithmeticScanner provenance and detection capabilities

use anyhow::Result;
use tameshi_scanners::{
    core::{ScannerConfig, ContractInfo, AnalysisContext},
    representations::RepresentationBundle,
    UncheckedArithmeticScanner,
    Scanner,
};

#[test]
fn test_unchecked_arithmetic_balance_underflow() -> Result<()> {
    const TEST_CONTRACT: &str = r#"
pragma solidity ^0.8.0;

contract VulnerableToken {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
    uint256 public totalSupply;

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        unchecked {
            balances[msg.sender] -= amount;
        }

        payable(msg.sender).transfer(amount);
    }

    function unsafeMint(address to, uint256 amount) public {
        unchecked {
            balances[to] += amount;
            totalSupply += amount;
        }
    }

    function unsafeTransfer(address to, uint256 amount) public {
        unchecked {
            balances[msg.sender] -= amount;
            balances[to] += amount;
        }
    }
}
"#;

    const FILENAME: &str = "VulnerableToken.sol";

    let contract_info = ContractInfo {
        name: "VulnerableToken".to_string(),
        source_path: Some(FILENAME.to_string()),
        source_code: None,
        compiler_version: None,
        optimization_enabled: false,
    };

    let bundle = RepresentationBundle::new();
    let config = ScannerConfig::default();
    let context = AnalysisContext::new_with_source(bundle, contract_info, config, TEST_CONTRACT);

    let scanner = UncheckedArithmeticScanner::new();
    let findings = scanner.scan(&context)?;

    println!("\n[unchecked-arithmetic] Detected {} findings", findings.len());

    assert!(
        !findings.is_empty(),
        "Should detect unchecked arithmetic vulnerabilities"
    );

    let mut found_balance_underflow = false;
    let mut found_totalsupply_overflow = false;

    for finding in &findings {
        println!("  - {}: {}", finding.severity, finding.title);

        assert!(
            finding.metadata.is_some(),
            "Finding '{}' should have metadata",
            finding.title
        );

        if finding.title.contains("balance") && finding.title.contains("-=") {
            found_balance_underflow = true;
            assert_eq!(
                finding.severity,
                tameshi_scanners::core::Severity::Critical,
                "Balance underflow should be Critical severity"
            );
        }

        if finding.title.contains("totalSupply") {
            found_totalsupply_overflow = true;
            assert!(
                finding.severity >= tameshi_scanners::core::Severity::High,
                "TotalSupply modification should be at least High severity"
            );
        }

        for location in &finding.locations {
            assert_eq!(location.file, FILENAME);
            assert!(location.line > 0 && location.line < 100);
            assert!(location.snippet.is_some());

            if let Some(ref snippet) = location.snippet {
                println!("    Location: {}:{} - {}", location.file, location.line, snippet);
            }
        }
    }

    assert!(
        found_balance_underflow,
        "Should detect balance underflow vulnerability"
    );

    assert!(
        found_totalsupply_overflow,
        "Should detect totalSupply overflow vulnerability"
    );

    Ok(())
}

#[test]
fn test_unchecked_loop_counter_overflow() -> Result<()> {
    const TEST_CONTRACT: &str = r#"
pragma solidity ^0.8.0;

contract LoopVulnerable {
    uint256[] public data;

    function dangerousLoop(uint256 start, uint256 increment) public {
        unchecked {
            for (uint256 i = start; i < data.length; i += increment) {
                data[i] = i * 2;
            }
        }
    }

    function nestedUnchecked() public {
        unchecked {
            uint256 counter = 0;
            while (counter < 100) {
                counter++;
            }
        }
    }
}
"#;

    const FILENAME: &str = "LoopVulnerable.sol";

    let contract_info = ContractInfo {
        name: "LoopVulnerable".to_string(),
        source_path: Some(FILENAME.to_string()),
        source_code: None,
        compiler_version: None,
        optimization_enabled: false,
    };

    let bundle = RepresentationBundle::new();
    let config = ScannerConfig::default();
    let context = AnalysisContext::new_with_source(bundle, contract_info, config, TEST_CONTRACT);

    let scanner = UncheckedArithmeticScanner::new();
    let findings = scanner.scan(&context)?;

    println!("\n[unchecked-arithmetic] Loop counter findings: {}", findings.len());

    assert!(
        !findings.is_empty(),
        "Should detect loop counter vulnerabilities"
    );

    let loop_findings: Vec<_> = findings.iter()
        .filter(|f| f.title.contains("loop counter"))
        .collect();

    assert!(
        !loop_findings.is_empty(),
        "Should specifically detect loop counter arithmetic"
    );

    for finding in loop_findings {
        println!("  - Loop finding: {}", finding.title);
        assert!(finding.description.contains("loop") || finding.description.contains("counter"));
    }

    Ok(())
}

#[test]
fn test_unchecked_array_index_manipulation() -> Result<()> {
    const TEST_CONTRACT: &str = r#"
pragma solidity ^0.8.0;

contract ArrayManipulation {
    uint256[] public values;
    mapping(uint256 => uint256) public data;

    function unsafeArrayAccess(uint256 index, uint256 offset) public view returns (uint256) {
        unchecked {
            uint256 actualIndex = index + offset;
            return values[actualIndex];
        }
    }

    function unsafeMappingUpdate(uint256 key, uint256 delta) public {
        unchecked {
            data[key] += delta;
        }
    }
}
"#;

    const FILENAME: &str = "ArrayManipulation.sol";

    let contract_info = ContractInfo {
        name: "ArrayManipulation".to_string(),
        source_path: Some(FILENAME.to_string()),
        source_code: None,
        compiler_version: None,
        optimization_enabled: false,
    };

    let bundle = RepresentationBundle::new();
    let config = ScannerConfig::default();
    let context = AnalysisContext::new_with_source(bundle, contract_info, config, TEST_CONTRACT);

    let scanner = UncheckedArithmeticScanner::new();
    let findings = scanner.scan(&context)?;

    println!("\n[unchecked-arithmetic] Array/Mapping findings: {}", findings.len());

    for finding in &findings {
        println!("  - {}: {}", finding.severity, finding.title);

        if finding.title.contains("array") || finding.title.contains("mapping") {
            assert!(
                finding.severity >= tameshi_scanners::core::Severity::Medium,
                "Array/mapping operations should be at least Medium severity"
            );
        }
    }

    Ok(())
}

#[test]
fn test_safe_unchecked_operations() -> Result<()> {
    const TEST_CONTRACT: &str = r#"
pragma solidity ^0.8.0;

contract SafeUnchecked {
    function safeBoundedLoop() public pure returns (uint256) {
        uint256 result = 0;

        unchecked {
            for (uint256 i = 0; i < 10; i++) {
                result += i;
            }
        }

        return result;
    }

    function safeConstantArithmetic() public pure returns (uint256) {
        unchecked {
            uint256 a = 100;
            uint256 b = 50;
            return a - b;
        }
    }
}
"#;

    const FILENAME: &str = "SafeUnchecked.sol";

    let contract_info = ContractInfo {
        name: "SafeUnchecked".to_string(),
        source_path: Some(FILENAME.to_string()),
        source_code: None,
        compiler_version: None,
        optimization_enabled: false,
    };

    let bundle = RepresentationBundle::new();
    let config = ScannerConfig::default();
    let context = AnalysisContext::new_with_source(bundle, contract_info, config, TEST_CONTRACT);

    let scanner = UncheckedArithmeticScanner::new();
    let findings = scanner.scan(&context)?;

    println!("\n[unchecked-arithmetic] Safe operations findings: {}", findings.len());

    let high_severity_findings: Vec<_> = findings.iter()
        .filter(|f| f.severity >= tameshi_scanners::core::Severity::High)
        .collect();

    assert!(
        high_severity_findings.is_empty(),
        "Safe unchecked operations should not generate high severity findings"
    );

    Ok(())
}

#[test]
fn test_unchecked_with_validation() -> Result<()> {
    const TEST_CONTRACT: &str = r#"
pragma solidity ^0.8.0;

contract ValidatedUnchecked {
    mapping(address => uint256) public balances;

    function safeWithdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        require(amount > 0, "Amount must be positive");

        unchecked {
            balances[msg.sender] -= amount;
        }
    }

    function unsafeWithdraw(uint256 amount) public {
        unchecked {
            balances[msg.sender] -= amount;
        }
    }
}
"#;

    const FILENAME: &str = "ValidatedUnchecked.sol";

    let contract_info = ContractInfo {
        name: "ValidatedUnchecked".to_string(),
        source_path: Some(FILENAME.to_string()),
        source_code: None,
        compiler_version: None,
        optimization_enabled: false,
    };

    let bundle = RepresentationBundle::new();
    let config = ScannerConfig::default();
    let context = AnalysisContext::new_with_source(bundle, contract_info, config, TEST_CONTRACT);

    let scanner = UncheckedArithmeticScanner::new();
    let findings = scanner.scan(&context)?;

    println!("\n[unchecked-arithmetic] Validated vs unvalidated findings: {}", findings.len());

    let unsafe_withdraw_findings: Vec<_> = findings.iter()
        .filter(|f| f.metadata.as_ref()
            .map(|m| m.affected_functions.contains(&"unsafeWithdraw".to_string()))
            .unwrap_or(false))
        .collect();

    let safe_withdraw_findings: Vec<_> = findings.iter()
        .filter(|f| f.metadata.as_ref()
            .map(|m| m.affected_functions.contains(&"safeWithdraw".to_string()))
            .unwrap_or(false))
        .collect();

    assert!(
        !unsafe_withdraw_findings.is_empty(),
        "Should detect unvalidated balance subtraction"
    );

    for finding in safe_withdraw_findings {
        assert!(
            finding.confidence <= tameshi_scanners::core::Confidence::Low,
            "Validated operations should have lower confidence scores"
        );
    }

    Ok(())
}