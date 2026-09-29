//! Digests as text: the three widths, and what a malformed one is.
//!
//! A SHA-512 arrives from a registry and a SHA-1 from an npm lockfile old enough to predate
//! `integrity` (`src/digest.rs`), so both are parsed from text somebody else wrote. A digest of the
//! wrong width parsed as a shorter or longer one would compare unequal to everything and look like
//! a mismatch rather than a malformed input; the error names the length found instead.

use trigon_core::{Digest, MultiDigest, ParseDigestError, Sha1, Sha512};

#[test]
fn each_width_refuses_every_other_width_and_names_the_length_it_found() {
    let hex = |n: usize| "ab".repeat(n / 2);
    for n in [0, 40, 64, 126, 128, 130] {
        let sha1 = Sha1::from_hex(&hex(n));
        let sha256 = Digest::from_hex(&hex(n));
        let sha512 = Sha512::from_hex(&hex(n));
        assert_eq!(sha1.is_ok(), n == 40, "sha1 from {n}");
        assert_eq!(sha256.is_ok(), n == 64, "sha256 from {n}");
        assert_eq!(sha512.is_ok(), n == 128, "sha512 from {n}");
        for e in [sha1.err(), sha256.err(), sha512.err()]
            .into_iter()
            .flatten()
        {
            assert!(
                matches!(e, ParseDigestError::Length(found) if found == n),
                "{e:?}"
            );
            assert!(
                e.to_string().starts_with(&format!("{n} hex characters")),
                "{e}"
            );
        }
    }
}

#[test]
fn a_non_hex_character_is_refused_at_every_width() {
    let with_g_at = |len: usize, at: usize| {
        let mut s = "0".repeat(len);
        s.replace_range(at..at + 1, "g");
        s
    };
    assert!(matches!(
        Sha1::from_hex(&with_g_at(40, 39)),
        Err(ParseDigestError::Char)
    ));
    assert!(matches!(
        Digest::from_hex(&with_g_at(64, 0)),
        Err(ParseDigestError::Char)
    ));
    assert!(matches!(
        Sha512::from_hex(&with_g_at(128, 77)),
        Err(ParseDigestError::Char)
    ));
    // Multi-byte text of the right byte length is not hex either.
    assert!(matches!(
        Sha1::from_hex(&"é".repeat(20)),
        Err(ParseDigestError::Char)
    ));
}

#[test]
fn upper_case_hex_is_read_and_written_back_lower_case() {
    let upper = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709";
    let d = Sha1::from_hex(upper).unwrap();
    assert_eq!(d.to_hex(), upper.to_ascii_lowercase());

    let upper = "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE\
                 47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E";
    let d = Sha512::from_hex(upper).unwrap();
    assert_eq!(d.to_hex(), upper.to_ascii_lowercase());
}

#[test]
fn a_digest_debugs_as_its_hex_so_a_log_line_names_it() {
    let d = Digest::from_bytes([0xab; 32]);
    assert_eq!(format!("{d:?}"), format!("Digest({})", "ab".repeat(32)));
    assert_eq!(d.to_string(), "ab".repeat(32));
    assert_eq!(
        format!("{:?}", Sha512([0xcd; 64])),
        format!("Sha512({})", "cd".repeat(64))
    );
    assert_eq!(
        format!("{:?}", Sha1([0xef; 20])),
        format!("Sha1({})", "ef".repeat(20))
    );
}

#[test]
fn a_malformed_digest_in_a_document_is_refused_rather_than_read() {
    let ok = format!(
        r#"{{"sha256":"{}","sha512":"{}"}}"#,
        "11".repeat(32),
        "22".repeat(64)
    );
    let m: MultiDigest = serde_json::from_str(&ok).unwrap();
    assert_eq!(m.sha512, Some(Sha512([0x22; 64])));
    assert_eq!(serde_json::to_string(&m).unwrap(), ok);

    // A SHA-256 where the SHA-512 goes: the right shape of string, the wrong width.
    let short = format!(
        r#"{{"sha256":"{}","sha512":"{}"}}"#,
        "11".repeat(32),
        "22".repeat(32)
    );
    let e = serde_json::from_str::<MultiDigest>(&short).unwrap_err();
    assert!(e.to_string().contains("64 hex characters"), "{e}");

    let sha1: Sha1 = serde_json::from_str(&format!("\"{}\"", "33".repeat(20))).unwrap();
    assert_eq!(sha1, Sha1([0x33; 20]));
    assert!(serde_json::from_str::<Sha1>(&format!("\"{}\"", "33".repeat(19))).is_err());
    assert!(serde_json::from_str::<Sha1>(&format!("\"{}zz\"", "33".repeat(19))).is_err());
}
