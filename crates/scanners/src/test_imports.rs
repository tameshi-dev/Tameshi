//! Test file to prove all import paths work correctly after flattening refactor
#![allow(unused_imports, dead_code)]

use crate::{
    get_functions_with_modifiers, ASTDoSVulnerabilitiesScanner, SimpleTimestampScanner,
    SourceAccessControlScanner, SourceClassicReentrancyScanner, SourceDangerousFunctionsScanner,
    SourceDelegatecallScanner, SourceDoSVulnerabilitiesScanner, SourceGasLimitDoSScanner,
    SourceIntegerOverflowScanner, SourceLoopReentrancyScanner, SourceMissingAccessControlScanner,
    SourceTimeVulnerabilitiesScanner, SourceUncheckedOverflowScanner, SourceUncheckedReturnScanner,
};

use crate::source::{
    SourceClassicReentrancyScanner as ClassicScanner1, SourceLoopReentrancyScanner as LoopScanner1,
};

use crate::source::{
    classic_reentrancy::SourceClassicReentrancyScanner as ClassicScanner3,
    loop_reentrancy::SourceLoopReentrancyScanner as LoopScanner3,
    SourceClassicReentrancyScanner as ClassicScanner2, SourceLoopReentrancyScanner as LoopScanner2,
};

use crate::{IRAccessControlScanner, IRReentrancyScanner, IRUncheckedReturnScanner};

#[test]
fn test_all_import_paths_compile() {
    // This test exists solely to verify all import paths compile correctly
    // The imports above prove the module flattening works as expected
}
