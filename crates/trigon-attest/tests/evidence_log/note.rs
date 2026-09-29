//! C2SP signed notes and the log key, against Go's vectors, and every refusal.

use serde_json::Value;
use trigon_attest::LogVkey;
use trigon_attest::log::note::MAX_SIGNATURES;
use trigon_attest::log::{LogError, LogSigner, SignedNote};

use crate::common::err;

const VECTORS: &str = include_str!("../../testdata/log/note-go.json");

fn v(key: &str) -> String {
    let all: Value = serde_json::from_str(VECTORS).unwrap();
    all[key].as_str().unwrap().to_string()
}

fn peter() -> LogVkey {
    LogVkey::parse(&v("vkey")).unwrap()
}

fn enoch() -> LogVkey {
    LogVkey::parse(&v("enochVkey")).unwrap()
}

#[test]
fn gos_signed_note_verifies_and_writes_back_byte_for_byte() {
    let note = SignedNote::parse(v("note").as_bytes()).unwrap();
    note.verify(&peter()).unwrap();
    assert_eq!(note.text(), v("text"));
    assert_eq!(note.signatures().len(), 1);
    assert_eq!(note.signatures()[0].name(), "PeterNeumann");
    assert_eq!(note.signatures()[0].key_hash(), [0xc7, 0x4f, 0x20, 0xa3]);
    assert_eq!(note.to_string(), v("note"));
}

/// Ed25519 is deterministic, so signing Go's text with Go's private key must give Go's line: the
/// private key format, the key hash, the text a signature covers and the line's encoding, all at
/// once, against an implementation that is not this one.
#[test]
fn gos_private_key_signs_gos_note_byte_for_byte() {
    let signer = LogSigner::from_skey(&v("skey")).unwrap();
    assert_eq!(signer.vkey().to_string(), v("vkey"));
    let note = SignedNote::sign(&v("text"), &signer).unwrap();
    assert_eq!(note.to_string(), v("note"));
    assert_eq!(signer.to_skey(), v("skey"));
}

/// The line offered as Go's vector for this note is not Go's. It names the key hash caf4d2a3, and
/// PeterNeumann's is c74f20a3, so it is a signature by some other key and a note carrying only it
/// is not signed by PeterNeumann. Given PeterNeumann's hash, its bytes still do not verify.
#[test]
fn a_signature_line_whose_hash_names_another_key_is_not_the_pinned_keys() {
    let line = v("notTheVector");
    let note = SignedNote::parse(format!("{}\n{line}", v("text")).as_bytes()).unwrap();
    assert_eq!(note.signatures()[0].key_hash(), [0xca, 0xf4, 0xd2, 0xa3]);
    let e = note.verify(&peter()).unwrap_err();
    assert!(matches!(e, LogError::Unverified(_)), "{e}");
    assert!(e.to_string().contains("PeterNeumann+caf4d2a3"), "{e}");

    // With PeterNeumann's hash in front of the same 64 bytes, the line names the key and fails
    // under it, which refuses the note outright.
    use base64::Engine as _;
    let b64 = line.rsplit(' ').next().unwrap().trim_end();
    let mut raw = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .unwrap();
    raw[..4].copy_from_slice(&[0xc7, 0x4f, 0x20, 0xa3]);
    let renamed = format!(
        "{}\n\u{2014} PeterNeumann {}\n",
        v("text"),
        base64::engine::general_purpose::STANDARD.encode(raw)
    );
    let e = SignedNote::parse(renamed.as_bytes())
        .unwrap()
        .verify(&peter())
        .unwrap_err();
    assert!(matches!(e, LogError::BadSignature(_)), "{e}");
}

#[test]
fn a_cosignature_by_a_key_not_pinned_is_read_past() {
    let note = SignedNote::parse(v("cosigned").as_bytes()).unwrap();
    assert_eq!(note.signatures().len(), 2);
    note.verify(&peter()).unwrap();
    note.verify(&enoch()).unwrap();
    assert_eq!(note.to_string(), v("cosigned"));
}

/// Go's own case: four bytes inserted into a signature by the pinned key refuse the note.
#[test]
fn a_line_by_the_pinned_key_that_does_not_verify_refuses_the_note() {
    let (text, peter_line, enoch_line) = (v("text"), v("peterLine"), v("enochLine"));
    let bad = format!("{}ABCD{}", &peter_line[..60], &peter_line[60..]);
    let e = SignedNote::parse(format!("{text}\n{bad}").as_bytes())
        .unwrap()
        .verify(&peter())
        .unwrap_err();
    assert!(matches!(e, LogError::BadSignature(_)), "{e}");

    // A bad line by a key not pinned does not matter to a verifier that pinned another, and
    // refuses the note for one that pinned it.
    let bad_enoch = format!("{}ABCD{}", &enoch_line[..60], &enoch_line[60..]);
    let note = format!("{text}\n{peter_line}{peter_line}{enoch_line}{bad_enoch}");
    let note = SignedNote::parse(note.as_bytes()).unwrap();
    assert_eq!(
        note.signatures().len(),
        3,
        "a line given twice is read once"
    );
    note.verify(&peter()).unwrap();
    assert!(matches!(
        note.verify(&enoch()).unwrap_err(),
        LogError::BadSignature(_)
    ));
}

/// Stricter than Go, which checks the first line by a key and skips the rest: an honest signer
/// writes one line, so a second, different line by the same key was written by something else.
#[test]
fn every_line_naming_the_pinned_key_must_verify() {
    let signer = LogSigner::from_skey(&v("skey")).unwrap();
    let other = LogSigner::from_seed("PeterNeumann", [9; 32]).unwrap();
    let note = SignedNote::sign(&v("text"), &signer).unwrap();
    // A line by another key under the same name and hash cannot be made without a collision, so
    // take a real signature over other text and give it this key's hash.
    let forged = SignedNote::sign("other text\n", &signer)
        .unwrap()
        .to_string();
    let forged_line = forged.lines().last().unwrap();
    let two = format!("{}{forged_line}\n", note);
    let e = SignedNote::parse(two.as_bytes())
        .unwrap()
        .verify(&peter())
        .unwrap_err();
    assert!(matches!(e, LogError::BadSignature(_)), "{e}");
    // A different key under the same name has a different hash, and is read past.
    let cosigned = note.cosign(&other).unwrap();
    cosigned.verify(&peter()).unwrap();
}

#[test]
fn a_note_whose_text_changed_does_not_verify() {
    let altered = v("note").replacen("problem", "Problem", 1);
    let e = SignedNote::parse(altered.as_bytes())
        .unwrap()
        .verify(&peter())
        .unwrap_err();
    assert!(matches!(e, LogError::BadSignature(_)), "{e}");
}

#[test]
fn a_malformed_note_is_refused_with_the_reason() {
    let (text, line) = (v("text"), v("peterLine"));
    let b64 = line.rsplit(' ').next().unwrap().trim_end().to_string();
    let cases: Vec<(Vec<u8>, &str)> = vec![
        // Go's own malformed cases first.
        (text.clone().into_bytes(), "no blank line"),
        (format!("{text}\n").into_bytes(), "no signature lines"),
        (
            format!("{text}\n{}", &line[..line.len() - 1]).into_bytes(),
            "does not end in a newline",
        ),
        (
            format!("\x01{text}\n{line}").into_bytes(),
            "control character",
        ),
        (
            [b"\xff".as_slice(), format!("{text}\n{line}").as_bytes()].concat(),
            "not UTF-8",
        ),
        (
            format!("{text}\n\u{2014} Bad Name {b64}\n").into_bytes(),
            "is not base64",
        ),
        (
            format!("{text}\n{line}Unexpected line.\n").into_bytes(),
            "not a signature line",
        ),
        // And the rest of the rules.
        (
            format!("{text}\n\u{2014} Peter+Neumann {b64}\n").into_bytes(),
            "not a key name",
        ),
        (
            format!("{text}\n\u{2014}  {b64}\n").into_bytes(),
            "not a key name",
        ),
        (
            format!("{text}\n- PeterNeumann {b64}\n").into_bytes(),
            "not a signature line",
        ),
        (
            format!("{text}\n\u{2014} PeterNeumann AAAA\n").into_bytes(),
            "shorter than a key hash",
        ),
        (
            format!("{text}\n\u{2014} PeterNeumann\n").into_bytes(),
            "shorter than a key hash",
        ),
        // A blank line after the signatures makes it the separator, with nothing after it.
        (
            format!("{text}\n{line}\n").into_bytes(),
            "no signature lines",
        ),
        (format!("te\tx\n\n{line}").into_bytes(), "control character"),
        // The last character before the padding carries bits past the signature's end; set, the
        // base64 decodes to the same bytes and is not the canonical spelling of them.
        (
            format!(
                "{text}\n\u{2014} PeterNeumann {}N=\n",
                &b64[..b64.len() - 2]
            )
            .into_bytes(),
            "is not base64",
        ),
    ];
    for (msg, says) in cases {
        let shown = String::from_utf8_lossy(&msg).into_owned();
        let e = SignedNote::parse(&msg).unwrap_err();
        assert!(matches!(e, LogError::Malformed(_)), "{shown}: {e}");
        assert!(e.to_string().contains(says), "{shown}: {e}");
    }
}

#[test]
fn a_note_holds_at_most_a_hundred_signature_lines() {
    let (text, line) = (v("text"), v("peterLine"));
    // Go's case: a hundred and one lines, even of one signature, are not a note.
    let e = err(SignedNote::parse(
        format!("{text}\n{}", line.repeat(MAX_SIGNATURES + 1)).as_bytes(),
    ));
    assert!(e.contains("more than 100 signature lines"), "{e}");
    // A hundred are read.
    let mut lines = line.clone();
    for i in 1..MAX_SIGNATURES {
        let k = LogSigner::from_seed(&format!("witness{i}"), [i as u8; 32]).unwrap();
        let n = SignedNote::sign(&text, &k).unwrap().to_string();
        lines.push_str(n.lines().last().unwrap());
        lines.push('\n');
    }
    let note = SignedNote::parse(format!("{text}\n{lines}").as_bytes()).unwrap();
    assert_eq!(note.signatures().len(), MAX_SIGNATURES);
    note.verify(&peter()).unwrap();
    // And a hundred cannot be cosigned into a hundred and one.
    let more = LogSigner::from_seed("one-more", [200; 32]).unwrap();
    assert!(note.cosign(&more).is_err());
}

#[test]
fn text_that_cannot_be_a_note_is_not_signed() {
    let k = LogSigner::from_skey(&v("skey")).unwrap();
    for text in ["", "no newline", "tab\there\n"] {
        assert!(SignedNote::sign(text, &k).is_err(), "{text:?}");
    }
}

#[test]
fn cosigning_adds_a_line_and_replaces_one_by_the_same_key() {
    let peter_key = LogSigner::from_skey(&v("skey")).unwrap();
    let other = LogSigner::from_seed("Witness", [7; 32]).unwrap();
    let note = SignedNote::sign(&v("text"), &peter_key).unwrap();
    let twice = note.cosign(&other).unwrap();
    assert_eq!(twice.signatures().len(), 2);
    twice.verify(&peter()).unwrap();
    twice.verify(&other.vkey()).unwrap();
    // Cosigning again with a key already there changes nothing: the line is the same.
    assert_eq!(twice.cosign(&other).unwrap(), twice);
    // It reads back as written.
    let read = SignedNote::parse(twice.to_string().as_bytes()).unwrap();
    assert_eq!(read, twice);
}

#[test]
fn a_private_key_is_read_in_gos_format_and_a_bad_one_is_refused_unquoted() {
    let good = v("skey");
    // The key data is base64, which has `+` in it: everything after the fourth `+`.
    let data = good.splitn(5, '+').nth(4).unwrap().to_string();
    let seed_b64 = "AYEKFALVFGyNhPJEMzD1QIDr";
    for (skey, says) in [
        (good.replacen("PRIVATE", "PUBLIC", 1), "does not begin"),
        (good.replacen("+KEY+", "+KEYS+", 1), "does not begin"),
        (
            good.replacen("c74f20a3", "c74f20a4", 1),
            "names another key",
        ),
        (good.replacen("c74f20a3", "c74f20a", 1), "eight hex"),
        (good.replacen("PeterNeumann", "Peter Neumann", 1), "name"),
        (good.replacen("PeterNeumann", "", 1), "name"),
        (good.replacen(&data, "!!!", 1), "not base64"),
        (good.replacen(&data, "AQID", 1), "key data is 3 bytes"),
        // Type 0x02 and the same 32 bytes.
        (
            good.replacen(&data, "AoEKFALVFGyNhPJEMzD1QIDr+Y7hfZx09iUvxdXHKDFz", 1),
            "type is not Ed25519",
        ),
        (good.replacen(&data, "", 1), "empty"),
        (v("vkey"), "does not begin"),
    ] {
        let e = LogSigner::from_skey(&skey).unwrap_err().to_string();
        assert!(e.contains(says), "{skey}: {e}");
        assert!(!e.contains(seed_b64), "the refusal quotes the key: {e}");
    }
}

/// The likeliest mistake with a key file is the seed alone, without its type byte, and then the
/// byte where the type should be is the secret's first: no refusal shows any byte of it.
#[test]
fn a_bare_seed_is_refused_without_showing_a_byte_of_it() {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let good = v("skey");
    let data = good.splitn(5, '+').nth(4).unwrap().to_string();
    let seed = b64.decode(&data).unwrap()[1..].to_vec();
    assert_eq!(seed.len(), 32);
    for bare in [seed.clone(), seed[..31].to_vec()] {
        let skey = good.replacen(&data, &b64.encode(&bare), 1);
        let e = LogSigner::from_skey(&skey).unwrap_err().to_string();
        assert!(e.contains("a log key's is 33"), "{e}");
        for b in &bare {
            // 0x01 is the type byte the refusal names as what it wanted.
            if *b != 0x01 {
                assert!(
                    !e.contains(&format!("0x{b:02x}")),
                    "byte {b:#04x} shown: {e}"
                );
            }
        }
        assert!(!e.contains(&b64.encode(&bare)), "{e}");
    }
    // Of the right length, the type byte is still not shown: a secret of 33 bytes is as secret.
    let mut typed = vec![0x81];
    typed.extend_from_slice(&seed);
    let e = LogSigner::from_skey(&good.replacen(&data, &b64.encode(&typed), 1))
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("type is not Ed25519") && !e.contains("0x81"),
        "{e}"
    );
}

/// A signer's name is held to the rule its verifier key is, so a signer exists only where a key a
/// client can pin does: a control character that a signature line may carry is no name for a key
/// Trigon makes, and `vkey()` never fails.
#[test]
fn a_signer_is_made_only_under_a_name_its_verifier_key_can_carry() {
    for name in [
        "example.com/a\u{7f}b",
        "example.com/a\u{9b}b",
        "example.com/a\u{1b}b",
        "example.com/a\u{0}b",
        "with space",
        "with+plus",
        "",
    ] {
        let e = LogSigner::from_seed(name, [1; 32]).unwrap_err().to_string();
        assert!(e.contains("cannot name a log key"), "{name:?}: {e}");
        assert!(!e.chars().any(char::is_control), "{e:?}");
    }
    // Nor from a key file naming one.
    let skey = v("skey").replacen("PeterNeumann", "Peter\u{7f}Neumann", 1);
    let e = LogSigner::from_skey(&skey).unwrap_err().to_string();
    assert!(e.contains("control character"), "{e}");
}

proptest::proptest! {
    /// Whatever name a signer is made under, its verifier key reads back as itself.
    #[test]
    fn every_signer_has_a_verifier_key_that_reads_back(name in "\\PC{0,40}|[\\x00-\\x7f\\u{80}-\\u{a0}]{0,12}") {
        if let Ok(s) = LogSigner::from_seed(&name, [5; 32]) {
            let vkey = s.vkey();
            proptest::prop_assert_eq!(LogVkey::parse(&vkey.to_string()).unwrap(), vkey);
            let signed = SignedNote::sign("text\n", &s).unwrap();
            signed.verify(&s.vkey()).unwrap();
        }
    }
}

#[test]
fn a_private_key_file_is_one_line() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("log.key");
    std::fs::write(&path, format!("{}\n", v("skey"))).unwrap();
    let k = LogSigner::from_file(&path).unwrap();
    assert_eq!(k.vkey().to_string(), v("vkey"));

    std::fs::write(&path, format!("{}\n{}\n", v("skey"), v("skey"))).unwrap();
    let e = LogSigner::from_file(&path).unwrap_err().to_string();
    assert!(e.contains("single line"), "{e}");
    assert!(!e.contains("AYEKFALV"), "{e}");

    let e = LogSigner::from_file(&dir.path().join("absent"))
        .unwrap_err()
        .to_string();
    assert!(e.contains("could not read the log key"), "{e}");
}

#[test]
fn a_generated_key_writes_itself_in_gos_format_and_reads_back() {
    let k = LogSigner::generate("example.org/log").unwrap();
    let skey = k.to_skey();
    assert!(skey.starts_with("PRIVATE+KEY+example.org/log+"), "{skey}");
    let back = LogSigner::from_skey(&skey).unwrap();
    assert_eq!(back.vkey(), k.vkey());
    assert_eq!(&back.verifying_key(), k.vkey().verifying_key());
    // Its verifier key is one `LogVkey::parse` reads, and verifies its notes.
    let vkey = LogVkey::parse(&k.vkey().to_string()).unwrap();
    SignedNote::sign("hello\n", &back)
        .unwrap()
        .verify(&vkey)
        .unwrap();
    // A name a note cannot carry is refused.
    assert!(LogSigner::generate("with space").is_err());
    assert!(LogSigner::generate("with+plus").is_err());
    assert!(LogSigner::generate("").is_err());
}

#[test]
fn a_signers_debug_form_shows_nothing_of_the_key() {
    let k = LogSigner::from_skey(&v("skey")).unwrap();
    let shown = format!("{k:?}");
    assert!(
        shown.contains("PeterNeumann") && shown.contains("c74f20a3"),
        "{shown}"
    );
    assert!(
        !shown.contains("AYEKFALV") && !shown.contains("seed"),
        "{shown}"
    );
}

/// A signature line holds a key hash and at least one byte of signature, as Go reads it: one byte
/// is enough to be read, by a key not pinned read past, and by the pinned key refused when it is
/// checked, since the length a key type needs is that key's to hold it to. The key hash alone is
/// not a signature line.
#[test]
fn a_signature_line_holds_a_key_hash_and_at_least_one_byte() {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let (text, line) = (v("text"), v("peterLine"));
    let one_byte = format!("\u{2014} Witness {}\n", b64.encode([1, 2, 3, 4, 5]));
    let note = SignedNote::parse(format!("{text}\n{line}{one_byte}").as_bytes()).unwrap();
    assert_eq!(note.signatures().len(), 2);
    assert_eq!(note.signatures()[1].name(), "Witness");
    assert_eq!(note.signatures()[1].key_hash(), [1, 2, 3, 4]);
    note.verify(&peter()).unwrap();

    let peters = format!(
        "\u{2014} PeterNeumann {}\n",
        b64.encode([0xc7, 0x4f, 0x20, 0xa3, 5])
    );
    let note = SignedNote::parse(format!("{text}\n{peters}").as_bytes()).unwrap();
    let e = note.verify(&peter()).unwrap_err();
    assert!(matches!(e, LogError::BadSignature(_)), "{e}");

    let hash_alone = format!("\u{2014} Witness {}\n", b64.encode([1, 2, 3, 4]));
    let e = err(SignedNote::parse(
        format!("{text}\n{line}{hash_alone}").as_bytes(),
    ));
    assert!(
        e.contains("is 4 bytes, shorter than a key hash and a signature"),
        "{e}"
    );
}
