//! Context-bound publish: optional main-head binding for selective apply.
//!
//! `head(main)` is a content fingerprint of the caller's active consensus rows.
//! `selective_apply` calls [`authorize_apply`] with that fingerprint before it
//! opens a write transaction. A mismatch is [`MemoriaError::StaleBase`] and
//! does not mutate main. Omitting `expected_base` skips the check.

use memoria_core::MemoriaError;
use sha2::{Digest, Sha256};

/// One active consensus row that contributes to [`main_head_fingerprint`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainHeadRecord {
    pub memory_id: String,
    pub memory_type: String,
    pub content: String,
}

/// Stable `mh1:` fingerprint of active main rows.
///
/// Encoding (so a client can reproduce the token the server checks):
/// SHA-256 over `b"memoria-main-head-v1\\0"` followed by each row, sorted by
/// `(memory_id, memory_type, content)` as raw UTF-8:
/// `memory_id 0xFF memory_type 0xFF content 0x00`.
/// The digest is lowercase hex with an `mh1:` prefix.
///
/// Inactive rows are not part of the head. Row order does not change the
/// fingerprint. An empty active set has a stable fingerprint of its own.
pub fn main_head_fingerprint(rows: &[MainHeadRecord]) -> String {
    let mut sorted: Vec<&MainHeadRecord> = rows.iter().collect();
    sorted.sort_by(|a, b| {
        a.memory_id
            .cmp(&b.memory_id)
            .then(a.memory_type.cmp(&b.memory_type))
            .then(a.content.cmp(&b.content))
    });

    let mut hasher = Sha256::new();
    hasher.update(b"memoria-main-head-v1\0");
    for row in sorted {
        hasher.update(row.memory_id.as_bytes());
        hasher.update([0xff]);
        hasher.update(row.memory_type.as_bytes());
        hasher.update([0xff]);
        hasher.update(row.content.as_bytes());
        hasher.update([0x00]);
    }

    let digest = hasher.finalize();
    let mut out = String::with_capacity(4 + digest.len() * 2);
    out.push_str("mh1:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

/// Blank or missing bases mean "do not bind". A supplied base is compared as
/// an opaque fingerprint, after trimming surrounding whitespace.
pub(crate) fn normalize_expected_base(expected_base: Option<&str>) -> Option<&str> {
    expected_base.map(str::trim).filter(|base| !base.is_empty())
}

/// Allow the apply when no base was supplied or it equals `current_head`.
///
/// `selective_apply` invokes this before `pool.begin()`. On `Err`, the caller
/// must return immediately and leave main unchanged.
pub fn authorize_apply(
    expected_base: Option<&str>,
    current_head: &str,
) -> Result<(), MemoriaError> {
    let Some(expected) = normalize_expected_base(expected_base) else {
        return Ok(());
    };
    if expected == current_head {
        return Ok(());
    }
    Err(MemoriaError::StaleBase {
        expected: expected.to_string(),
        current: current_head.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::{authorize_apply, main_head_fingerprint, MainHeadRecord};
    use crate::service::ApplySelection;
    use memoria_core::MemoriaError;

    const THETA_LOW: &str = "accept when the completion rate is at least the lower threshold";
    const THETA_HIGH: &str = "accept when the completion rate is at least the higher threshold";

    fn threshold(content: &str) -> MainHeadRecord {
        MainHeadRecord {
            memory_id: "ops-threshold".into(),
            memory_type: "semantic".into(),
            content: content.into(),
        }
    }

    fn draft() -> MainHeadRecord {
        MainHeadRecord {
            memory_id: "ops-draft".into(),
            memory_type: "semantic".into(),
            content: "draft reviewed against the lower threshold".into(),
        }
    }

    /// Same control flow as `GitForDataService::selective_apply`: authorize,
    /// then mutate. The `?` is what keeps a stale base from writing main.
    fn publish_draft(
        main: &mut Vec<MainHeadRecord>,
        selection: &ApplySelection,
        draft: MainHeadRecord,
    ) -> Result<(), MemoriaError> {
        let head = main_head_fingerprint(main);
        authorize_apply(selection.expected_base.as_deref(), &head)?;
        main.push(draft);
        Ok(())
    }

    #[test]
    fn expected_base_match_publishes_selection() {
        let mut main = vec![threshold(THETA_LOW)];
        let head = main_head_fingerprint(&main);
        let other = MainHeadRecord {
            memory_id: "ops-note".into(),
            memory_type: "semantic".into(),
            content: "unrelated consensus note".into(),
        };
        assert_eq!(
            main_head_fingerprint(&[threshold(THETA_LOW), other.clone()]),
            main_head_fingerprint(&[other, threshold(THETA_LOW)]),
        );
        assert!(head.starts_with("mh1:"));
        assert_ne!(head, main_head_fingerprint(&[threshold(THETA_HIGH)]));

        let selection = ApplySelection {
            adds: vec!["ops-draft".into()],
            expected_base: Some(head),
            ..ApplySelection::default()
        };
        publish_draft(&mut main, &selection, draft()).expect("matching base publishes");
        assert_eq!(main.len(), 2);
        assert_eq!(main[1].memory_id, "ops-draft");
    }

    #[test]
    fn expected_base_mismatch_is_stale_base_and_does_not_mutate() {
        let reviewed = vec![threshold(THETA_LOW)];
        let reviewed_head = main_head_fingerprint(&reviewed);
        let mut main = vec![threshold(THETA_HIGH)];
        let advanced_head = main_head_fingerprint(&main);
        let before = main.clone();

        let selection = ApplySelection {
            adds: vec!["ops-draft".into()],
            expected_base: Some(reviewed_head.clone()),
            ..ApplySelection::default()
        };
        let err = publish_draft(&mut main, &selection, draft()).expect_err("stale base");
        let message = err.to_string();
        match err {
            MemoriaError::StaleBase { expected, current } => {
                assert_eq!(expected, reviewed_head);
                assert_eq!(current, advanced_head);
                assert_ne!(expected, current);
                assert!(message.starts_with("StaleBase"));
            }
            other => panic!("expected StaleBase, got {other:?}"),
        }
        assert_eq!(main, before);
        assert!(main.iter().all(|row| row.memory_id != "ops-draft"));
    }

    #[test]
    fn omitted_expected_base_keeps_legacy_apply() {
        let parsed: ApplySelection =
            serde_json::from_str(r#"{"adds":["ops-draft"]}"#).expect("legacy body");
        assert!(parsed.expected_base.is_none());
        let explicit_null: ApplySelection =
            serde_json::from_str(r#"{"adds":["ops-draft"],"expected_base":null}"#).expect("null");
        assert!(explicit_null.expected_base.is_none());
        let blank: ApplySelection =
            serde_json::from_str(r#"{"adds":["ops-draft"],"expected_base":"  "}"#).expect("blank");
        let serialized = serde_json::to_value(&ApplySelection {
            adds: vec!["ops-draft".into()],
            ..ApplySelection::default()
        })
        .expect("serialize");
        assert!(serialized.get("expected_base").is_none());

        let mut main = vec![threshold(THETA_HIGH)];
        publish_draft(&mut main, &parsed, draft()).expect("omitted base still applies");
        assert!(main.iter().any(|row| row.memory_id == "ops-draft"));

        let mut blank_main = vec![threshold(THETA_HIGH)];
        publish_draft(&mut blank_main, &blank, draft()).expect("blank base is unbound");
        assert!(blank_main.iter().any(|row| row.memory_id == "ops-draft"));
    }
}
