//! Test file to prove all import paths work correctly after flattening refactor
#![allow(unused_imports, dead_code)]

use crate::{
    SourceLoopReentrancyScanner,
    SourceClassicReentrancyScanner,
    SourceIntegerOverflowScanner,
    SourceAccessControlScanner,
    SourceUncheckedReturnScanner,
    SourceDangerousFunctionsScanner,
    SourceTimeVulnerabilitiesScanner,
    SourceDoSVulnerabilitiesScanner,
    SourceMissingAccessControlScanner,
    SourceGasLimitDoSScanner,
    SourceDelegatecallScanner,
    SourceUncheckedOverflowScanner,
    SimpleTimestampScanner,
    ASTDoSVulnerabilitiesScanner,
    get_functions_with_modifiers,
};

use crate::source::{
    SourceLoopReentrancyScanner as LoopScanner1,
    SourceClassicReentrancyScanner as ClassicScanner1,
};

use crate::source::{
    SourceLoopReentrancyScanner as LoopScanner2,
    SourceClassicReentrancyScanner as ClassicScanner2,
    loop_reentrancy::SourceLoopReentrancyScanner as LoopScanner3,
    classic_reentrancy::SourceClassicReentrancyScanner as ClassicScanner3,
};

use crate::{
    IRReentrancyScanner,
    IRAccessControlScanner,
    IRUncheckedReturnScanner,
};

#[test]
fn test_all_import_paths_compile() {
    assert!(true);
}
