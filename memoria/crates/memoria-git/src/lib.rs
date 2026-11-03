pub mod base_binding;
pub mod service;
pub use base_binding::{authorize_apply, main_head_fingerprint, MainHeadRecord};
pub use service::{
    classify_diff_rows, ApplyResult, ApplySelection, ApplyUpdatePair, ClassifiedDiff, DiffConflict,
    DiffConflictSide, DiffItem, DiffRow, DiffUpdatedPair, GitForDataService, Snapshot,
};
