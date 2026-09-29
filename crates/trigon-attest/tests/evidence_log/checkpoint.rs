//! C2SP tlog-checkpoint: what we write, what we read, and what is refused.

use trigon_attest::log::merkle::empty_root;
use trigon_attest::log::{Checkpoint, LogError, LogSigner, SignedCheckpoint, SignedNote};

use crate::common::{ORIGIN, err, log_key};

const EMPTY_ROOT_B64: &str = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

#[test]
fn a_checkpoint_is_three_lines_and_no_extension_lines() {
    let cp = Checkpoint {
        origin: ORIGIN.into(),
        size: 1204,
        root: [7; 32],
    };
    assert_eq!(
        cp.body(),
        format!("{ORIGIN}\n1204\nBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\n")
    );
    assert_eq!(Checkpoint::parse(&cp.body()).unwrap(), cp);
}

/// `docs/19` §10 phase 5: the first commit of a repository holds a checkpoint of size 0 whose root
/// is the SHA-256 of the empty string.
#[test]
fn the_empty_checkpoint_signs_the_root_of_nothing() {
    let cp = Checkpoint::empty(ORIGIN);
    assert_eq!(cp.size, 0);
    assert_eq!(
        cp.root
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(cp.root, empty_root());
    assert_eq!(cp.body(), format!("{ORIGIN}\n0\n{EMPTY_ROOT_B64}\n"));
    let signed = SignedCheckpoint::sign(&cp, &log_key()).unwrap();
    let opened = SignedCheckpoint::open(signed.to_string().as_bytes(), &log_key().vkey()).unwrap();
    assert_eq!(opened.checkpoint(), &cp);
}

/// Tolerated, and never trusted: an extension line changes nothing a reader keeps.
#[test]
fn extension_lines_are_read_past_and_not_kept() {
    let text = format!("{ORIGIN}\n5\n{EMPTY_ROOT_B64}\nextension one\n— witness timestamp\n");
    let cp = Checkpoint::parse(&text).unwrap();
    assert_eq!(cp.size, 5);
    assert_eq!(cp.body(), format!("{ORIGIN}\n5\n{EMPTY_ROOT_B64}\n"));
    // A note that carries them opens, and what it opens to has none.
    let note = SignedNote::sign(&text, &log_key()).unwrap();
    let opened = SignedCheckpoint::open(note.to_string().as_bytes(), &log_key().vkey()).unwrap();
    assert_eq!(opened.checkpoint(), &cp);
}

#[test]
fn a_malformed_checkpoint_is_refused_with_the_reason() {
    let root = EMPTY_ROOT_B64;
    for (text, says) in [
        (format!("{ORIGIN}\n0\n{root}"), "newline"),
        (format!("{ORIGIN}\n0\n"), "fewer than three lines"),
        (format!("{ORIGIN}\n"), "fewer than three lines"),
        (format!("\n0\n{root}\n"), "origin line is empty"),
        (format!("{ORIGIN}\n01\n{root}\n"), "leading zeros"),
        (format!("{ORIGIN}\n\n{root}\n"), "leading zeros"),
        (format!("{ORIGIN}\n-1\n{root}\n"), "decimal"),
        (format!("{ORIGIN}\n+1\n{root}\n"), "decimal"),
        (format!("{ORIGIN}\n1.0\n{root}\n"), "decimal"),
        (format!("{ORIGIN}\n 1\n{root}\n"), "decimal"),
        (
            format!("{ORIGIN}\n18446744073709551616\n{root}\n"),
            "decimal",
        ),
        (format!("{ORIGIN}\n1\n{}\n", &root[..40]), "32 bytes"),
        (format!("{ORIGIN}\n1\nAAAA\n"), "32 bytes"),
        (format!("{ORIGIN}\n1\n!{}\n", &root[1..]), "32 bytes"),
        (format!("{ORIGIN}\n1\n{root}\n\nlater\n"), "empty line"),
    ] {
        let e = Checkpoint::parse(&text).unwrap_err();
        assert!(matches!(e, LogError::Malformed(_)), "{text:?}: {e}");
        assert!(e.to_string().contains(says), "{text:?}: {e}");
    }
    // The largest size there is reads.
    let max = Checkpoint::parse(&format!("{ORIGIN}\n18446744073709551615\n{root}\n")).unwrap();
    assert_eq!(max.size, u64::MAX);
}

#[test]
fn a_checkpoint_opens_only_under_its_own_origins_key() {
    let cp = Checkpoint {
        origin: ORIGIN.into(),
        size: 3,
        root: [1; 32],
    };
    let signed = SignedCheckpoint::sign(&cp, &log_key()).unwrap().to_string();

    // Another key under the same name: its hash differs, so the note is not signed by the pin.
    let impostor = LogSigner::from_seed(ORIGIN, [99; 32]).unwrap();
    let e = SignedCheckpoint::open(signed.as_bytes(), &impostor.vkey()).unwrap_err();
    assert!(matches!(e, LogError::Unverified(_)), "{e}");

    // A note signed by the log's key whose first line names another log.
    let other = format!("example.com/other\n3\n{EMPTY_ROOT_B64}\n");
    let note = SignedNote::sign(&other, &log_key()).unwrap().to_string();
    let e = SignedCheckpoint::open(note.as_bytes(), &log_key().vkey()).unwrap_err();
    assert!(matches!(e, LogError::Unverified(_)), "{e}");
    assert!(e.to_string().contains("example.com/other"), "{e}");

    // And the signer refuses to make one.
    let theirs = Checkpoint {
        origin: "example.com/other".into(),
        ..cp.clone()
    };
    assert!(err(SignedCheckpoint::sign(&theirs, &log_key())).contains("log's origin"));

    // A size changed after signing.
    let altered = signed.replacen("\n3\n", "\n4\n", 1);
    let e = SignedCheckpoint::open(altered.as_bytes(), &log_key().vkey()).unwrap_err();
    assert!(matches!(e, LogError::BadSignature(_)), "{e}");
}

#[test]
fn a_note_that_is_not_a_checkpoint_does_not_open_as_one() {
    let note = SignedNote::sign(&format!("{ORIGIN}\nnot a size\n"), &log_key()).unwrap();
    let e = SignedCheckpoint::open(note.to_string().as_bytes(), &log_key().vkey()).unwrap_err();
    assert!(matches!(e, LogError::Malformed(_)), "{e}");
}
