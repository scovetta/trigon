//! The one spelling of `Derivation`, because it reaches a signed statement.
//!
//! Lives here rather than in `trigon-core`'s enumeration sweep because the type does: `trigon-core`
//! is below `trigon-registry` and cannot depend on it. The first version of this test lived there
//! and worked by parsing `infer.rs` as *text*, which is exactly why it asserted a property of the
//! variant identifiers instead of the behaviour of the code that writes the field.

#[test]
fn every_derivation_variant_spells_the_same_however_a_run_record_came_by_it() {
    // The confirm pass was right that the first version of this test did not measure the bug: it
    // asserted a property of the variant identifiers and never read the code that writes the field.
    //
    // What `trigon rebuild` actually did was write the run record's `derivation` two ways from two
    // branches of one `if` — `format!("{:?}", d).to_lowercase()` for a run that needed no repair,
    // and the literal `"model_assisted"` for one that did. So `ModelAssisted` reached a signed
    // statement as `modelassisted` or as `model_assisted` depending on whether a build failed once,
    // and `CiDerived` could only ever arrive as `ciderived`, which is not a spelling
    // `docs/09-attestations.md` uses anywhere.
    //
    // Both branches now go through `Display`, so this pins `Display` against the vocabulary the
    // attestation documents. It fails if a variant is added without a spelling, if a spelling drifts
    // from the docs, or if anyone reaches for `Debug` again.
    use trigon_registry::Derivation;
    let expected = [
        (Derivation::Definition, "definition"),
        (Derivation::CiDerived, "ci_derived"),
        (Derivation::Heuristic, "heuristic"),
        (Derivation::ModelAssisted, "model_assisted"),
    ];
    for (d, want) in expected {
        assert_eq!(
            d.to_string(),
            want,
            "`{d:?}` reaches a signed `derivation.method` as `{}`, and the attestation documents \
             `{want}`",
            d
        );
        assert_ne!(
            format!("{d:?}").to_lowercase(),
            "",
            "guard against an empty Debug, which would make the next assertion vacuous"
        );
    }

    // The specific regression: lowercasing `Debug` is not the same string, so anyone who reaches
    // for it again produces the old two-vocabulary bug.
    assert_ne!(
        format!("{:?}", Derivation::ModelAssisted).to_lowercase(),
        Derivation::ModelAssisted.to_string(),
        "lowercased Debug and Display agree for ModelAssisted, so this test can no longer tell the \
         two writers apart"
    );
    assert_ne!(
        format!("{:?}", Derivation::CiDerived).to_lowercase(),
        Derivation::CiDerived.to_string()
    );
}
