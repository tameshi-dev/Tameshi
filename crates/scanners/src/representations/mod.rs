//! Multiple program representations for multi-modal analysis
//!
//! Different views of smart contract code for scanner analysis. The key insight:
//! different vulnerability patterns are easier to detect in different representations.
//! Some patterns are obvious in source AST, others only appear in IR control flow.
//! The representation bundle lets scanners access whichever view they need, so a
//! single analysis pass can benefit from both source-level and IR-level insights.

pub mod bundle;
pub mod cranelift_adapter;
pub mod solidity_source;
pub mod traits;
pub mod source;

pub use bundle::{RepresentationBundle, RepresentationSet};
pub use solidity_source::SoliditySource;
pub use traits::{Representation, Visitable};
pub use source::{SourceRepresentation, FunctionInfo, LoopInfo, ExternalCallInfo, ModifierInfo};
