#[cfg(test)]
mod tests {
    use assert_cmd::prelude::*;
    use assert_cmd::Command;
    use predicates::prelude::*;

    #[test]
    fn test_if_statement_diamond_cfg() {
        let mut cmd = Command::cargo_bin("tameshi").unwrap();
        let solidity_code = r#"
            pragma solidity ^0.8.0;
            contract Simple {
                function f(uint256 x) public {
                    if (x > 10) {
                        x = x + 1;
                    } else {
                        x = x - 1;
                    }
                }
            }
        "#;
        cmd.args(["transform", "sol2ir", "--stdin", "--stdout"])
            .write_stdin(solidity_code)
            .assert()
            .success()
            .stdout(predicate::str::contains("blocks"));
    }

    #[test]
    fn test_while_loop_cfg() {
        let mut cmd = Command::cargo_bin("tameshi").unwrap();
        let solidity_code = r#"
            pragma solidity ^0.8.0;
            contract Simple {
                function f(uint256 x) public {
                    while (x < 10) {
                        x = x + 1;
                    }
                }
            }
        "#;
        cmd.args(["transform", "sol2ir", "--stdin", "--stdout"])
            .write_stdin(solidity_code)
            .assert()
            .success()
            .stdout(predicate::str::contains("blocks"));
    }
}
