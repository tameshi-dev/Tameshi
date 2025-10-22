use std::fs;
use std::io::Write;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn test_full_pipeline_command() {
    let temp_dir = TempDir::new().unwrap();
    let input_path = temp_dir.path().join("pipeline.sol");
    let output_path = temp_dir.path().join("pipeline.ir");

    let content = r#"
        pragma solidity ^0.8.0;
        contract PipelineTest {
            uint256 state;
            function updateState(uint256 newValue) public {
                require(newValue > 0, "Value must be positive");
                state = newValue;
            }
        }
    "#;

    fs::write(&input_path, content).unwrap();

    let output = Command::new("cargo")
        .args(&[
            "run",
            "-p",
            "tameshi-cli",
            "--",
            "pipeline",
            "--input",
            input_path.to_str().unwrap(),
            "--output",
            output_path.to_str().unwrap(),
            "--verbose",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(
        output.status.success(),
        "Command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output_path.exists(),
        "Cranelift IR output file was not created"
    );

    let ir_content = fs::read_to_string(&output_path).unwrap();
    assert!(
        ir_content.contains("PipelineTest"),
        "IR should contain contract name"
    );
}


#[test]
fn test_transform_sol2ir_command() {
    let temp_dir = TempDir::new().unwrap();
    let input_path = temp_dir.path().join("test_ir.sol");
    let output_path = temp_dir.path().join("test_ir.json");

    let content = r#"
        pragma solidity ^0.8.0;
        contract IRTest {
            uint256 public counter;
            
            function increment() public {
                counter = counter + 1;
            }
            
            function getCount() public view returns (uint256) {
                return counter;
            }
        }
    "#;

    fs::write(&input_path, content).unwrap();

    let output = Command::new("cargo")
        .args(&[
            "run",
            "-p",
            "tameshi-cli",
            "--",
            "transform",
            "sol2ir",
            "--input",
            input_path.to_str().unwrap(),
            "--output",
            output_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(
        output.status.success(),
        "Command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output_path.exists(), "Output file was not created");

    let output_content = fs::read_to_string(&output_path).unwrap();
    assert!(
        output_content.contains("IRTest"),
        "Output should contain contract name"
    );
    assert!(
        output_content.contains("increment"),
        "Output should contain function name"
    );
}

#[test]
fn test_transform_sol2ir_text_format() {
    let temp_dir = TempDir::new().unwrap();
    let input_path = temp_dir.path().join("test_text.sol");
    let output_path = temp_dir.path().join("test_text.ir");

    let content = r#"
        contract SimpleContract {
            function test() public pure returns (uint256) {
                return 42;
            }
        }
    "#;

    fs::write(&input_path, content).unwrap();

    let output = Command::new("cargo")
        .args(&[
            "run",
            "-p",
            "tameshi-cli",
            "--",
            "transform",
            "sol2ir",
            "--input",
            input_path.to_str().unwrap(),
            "--output",
            output_path.to_str().unwrap(),
            "--format",
            "text",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(
        output.status.success(),
        "Command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output_path.exists(), "Output file was not created");

    let output_content = fs::read_to_string(&output_path).unwrap();
    assert!(
        output_content.contains("SimpleContract"),
        "Output should contain contract name"
    );
    assert!(
        output_content.contains("test"),
        "Output should contain function name"
    );
}

#[test]
fn test_sol2ir_stdin_stdout() {
    let content = r#"
        contract StdinTest {
            uint256 value;
            
            constructor(uint256 _value) {
                value = _value;
            }
        }
    "#;

    let mut child = Command::new("cargo")
        .args(&[
            "run",
            "-p",
            "tameshi-cli",
            "--",
            "transform",
            "sol2ir",
            "--stdin",
            "--stdout",
            "--format",
            "json",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn command");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(content.as_bytes()).unwrap();
    }

    let output = child
        .wait_with_output()
        .expect("Failed to wait for command");

    assert!(
        output.status.success(),
        "Command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("StdinTest"),
        "Expected contract name in JSON output"
    );
    assert!(
        stdout.contains("constructor"),
        "Expected constructor in output"
    );
}

#[test]
fn test_sol2ir_batch_processing() {
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("sol_contracts");
    let output_dir = temp_dir.path().join("ir_output");

    fs::create_dir_all(&input_dir).unwrap();

    let file1_path = input_dir.join("Token.sol");
    let content1 = r#"
        pragma solidity ^0.8.0;
        contract Token {
            mapping(address => uint256) public balances;
            
            function transfer(address to, uint256 amount) public {
                balances[msg.sender] -= amount;
                balances[to] += amount;
            }
        }
    "#;
    fs::write(&file1_path, content1).unwrap();

    let file2_path = input_dir.join("Storage.sol");
    let content2 = r#"
        contract Storage {
            uint256[] public data;
            
            function addData(uint256 value) public {
                data.push(value);
            }
        }
    "#;
    fs::write(&file2_path, content2).unwrap();

    let output = Command::new("cargo")
        .args(&[
            "run",
            "-p",
            "tameshi-cli",
            "--",
            "transform",
            "sol2ir",
            "--dir",
            input_dir.to_str().unwrap(),
            "--out-dir",
            output_dir.to_str().unwrap(),
            "--format",
            "json",
            "--verbose",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(
        output.status.success(),
        "Command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output_dir.exists(), "Output directory was not created");

    let token_output = output_dir.join("Token.json");
    assert!(token_output.exists(), "Token output file was not created");

    let storage_output = output_dir.join("Storage.json");
    assert!(
        storage_output.exists(),
        "Storage output file was not created"
    );

    let token_content = fs::read_to_string(&token_output).unwrap();
    assert!(
        token_content.contains("Token"),
        "Token output should contain contract name"
    );
    assert!(
        token_content.contains("transfer"),
        "Token output should contain transfer function"
    );

    let storage_content = fs::read_to_string(&storage_output).unwrap();
    assert!(
        storage_content.contains("Storage"),
        "Storage output should contain contract name"
    );
    assert!(
        storage_content.contains("addData"),
        "Storage output should contain addData function"
    );
}

#[test]
fn test_sol2ir_error_handling() {
    let temp_dir = TempDir::new().unwrap();
    let input_path = temp_dir.path().join("invalid.sol");

    let content = r#"
        this is not valid solidity code {
            function broken(
        }
    "#;

    fs::write(&input_path, content).unwrap();

    let output = Command::new("cargo")
        .args(&[
            "run",
            "-p",
            "tameshi-cli",
            "--",
            "transform",
            "sol2ir",
            "--input",
            input_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(
        !output.status.success(),
        "Command should have failed for invalid input"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Failed to transform") || stderr.contains("Transformation failed"),
        "Error message should indicate transformation failure"
    );
}

#[test]
fn test_sol2ir_empty_input() {
    let temp_dir = TempDir::new().unwrap();
    let input_path = temp_dir.path().join("empty.sol");

    fs::write(&input_path, "").unwrap();

    let output = Command::new("cargo")
        .args(&[
            "run",
            "-p",
            "tameshi-cli",
            "--",
            "transform",
            "sol2ir",
            "--input",
            input_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(
        !output.status.success(),
        "Command should have failed for empty input"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("empty") || stderr.contains("Empty"),
        "Error message should indicate empty input"
    );
}
