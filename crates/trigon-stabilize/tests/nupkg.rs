//! The `.nupkg` packaging passes: what two `dotnet pack` runs over one source disagree about, and
//! nothing else.
//!
//! A `.nupkg` is an OPC zip. `profiles.rs` names what differs between packs of identical source —
//! the gallery's signature, a per-pack GUID in a member name and the relationship ids beside it,
//! the packing machine's name, its line endings, its collation, the git ref it built from, and
//! NuGetizer's include markers — and each pass here is held to removing exactly that: two packs of
//! the same package agree, a real difference still shows, and a member the pass has nothing to do
//! with is not touched or claimed. A pass that claims an entry it did not change puts itself in
//! `applied`, which is what a verdict's tier is read from.

use trigon_archive::{Limits, parse, serialize};
use trigon_core::{Format, Note, RiskTier};
use trigon_stabilize::{Applied, StabilizerSet, apply, profile};

fn zip(members: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write as _;
    let mut w = zip_crate::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts: zip_crate::write::FileOptions<'_, ()> = zip_crate::write::FileOptions::default()
        .compression_method(zip_crate::CompressionMethod::Deflated)
        .last_modified_time(zip_crate::DateTime::from_date_and_time(2024, 1, 2, 3, 4, 6).unwrap());
    for (name, body) in members {
        w.start_file(*name, opts).unwrap();
        w.write_all(body).unwrap();
    }
    w.finish().unwrap().into_inner()
}

fn only(pass: &str) -> StabilizerSet {
    let set = profile("nupkg").unwrap().filtered(&[pass.to_string()], &[]);
    assert_eq!(
        set.members.len(),
        1,
        "no pass `{pass}` in the nupkg profile"
    );
    set
}

fn nupkg() -> StabilizerSet {
    profile("nupkg").unwrap()
}

fn stabilize(set: &StabilizerSet, bytes: Vec<u8>) -> (Vec<u8>, Vec<Applied>) {
    let mut notes: Vec<Note> = Vec::new();
    let mut p = parse(bytes, Format::Zip, &Limits::default(), &mut notes).unwrap();
    let applied = apply(set, &mut p.archive);
    (serialize(&p.archive, true).unwrap(), applied)
}

/// Every member of a stabilized package, by name, in the order it was written.
fn members(bytes: Vec<u8>) -> Vec<(String, Vec<u8>)> {
    let mut notes: Vec<Note> = Vec::new();
    let p = parse(bytes, Format::Zip, &Limits::default(), &mut notes).unwrap();
    p.archive
        .entries
        .iter()
        .map(|e| {
            (
                e.path.to_lossy().into_owned(),
                e.body_bytes().unwrap().into_owned(),
            )
        })
        .collect()
}

fn member(bytes: Vec<u8>, name: &str) -> String {
    let all = members(bytes);
    let Some((_, body)) = all.iter().find(|(n, _)| n == name) else {
        panic!(
            "no member `{name}` in {:?}",
            all.iter().map(|(n, _)| n).collect::<Vec<_>>()
        );
    };
    String::from_utf8(body.clone()).unwrap()
}

fn ids(applied: &[Applied]) -> Vec<&str> {
    applied.iter().map(|a| a.id.as_str()).collect()
}

// --- a whole package -----------------------------------------------------------------------------

const PSMDCP_DIR: &str = "package/services/metadata/core-properties/";
const CANONICAL_PSMDCP: &str = "package/services/metadata/core-properties/core.psmdcp";

/// What `dotnet pack` writes, with the three values that change on every pack as parameters.
struct Pack<'a> {
    guid: &'a str,
    rel_ids: [&'a str; 2],
    packer: &'a str,
    eol: &'a str,
    signed: bool,
}

impl Pack<'_> {
    fn bytes(&self) -> Vec<u8> {
        let rels = format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>{eol}<Relationships \
             xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">{eol}\
             <Relationship Type=\"http://schemas.microsoft.com/packaging/2010/07/manifest\" \
             Target=\"/Demo.nuspec\" Id=\"{a}\" />{eol}\
             <Relationship Type=\"http://schemas.openxmlformats.org/package/2006/relationships/\
             metadata/core-properties\" Target=\"/{PSMDCP_DIR}{guid}.psmdcp\" Id=\"{b}\" />{eol}\
             </Relationships>",
            eol = self.eol,
            a = self.rel_ids[0],
            b = self.rel_ids[1],
            guid = self.guid,
        );
        let core = format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>{eol}<coreProperties>{eol}\
             <dc:creator>Demo</dc:creator>{eol}<version>1.0.0</version>{eol}\
             <lastModifiedBy>{packer}</lastModifiedBy>{eol}</coreProperties>",
            eol = self.eol,
            packer = self.packer,
        );
        let nuspec = format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>{eol}<package>{eol}<metadata>{eol}\
             <id>Demo</id>{eol}<version>1.0.0</version>{eol}</metadata>{eol}</package>{eol}",
            eol = self.eol,
        );
        let psmdcp = format!("{PSMDCP_DIR}{}.psmdcp", self.guid);
        let mut m: Vec<(&str, Vec<u8>)> = vec![
            ("_rels/.rels", rels.into_bytes()),
            ("Demo.nuspec", nuspec.into_bytes()),
            ("lib/net8.0/Demo.txt", b"payload\n".to_vec()),
            (psmdcp.as_str(), core.into_bytes()),
            ("[Content_Types].xml", b"<Types/>".to_vec()),
        ];
        if self.signed {
            m.push((
                ".signature.p7s",
                b"\x30\x82gallery countersignature".to_vec(),
            ));
        }
        let refs: Vec<(&str, &[u8])> = m.iter().map(|(n, b)| (*n, b.as_slice())).collect();
        zip(&refs)
    }
}

/// The published package: packed on Windows by an old NuGet, countersigned by the gallery.
fn published() -> Pack<'static> {
    Pack {
        guid: "55d4e0b4ecfa412baa282881ce747f48",
        rel_ids: ["R2BEFEA914E60C8DE", "RB3A3BC5B3F3C4A39"],
        packer: "NuGet.Build.Tasks.Pack, Version=4.5.0.4;Microsoft Windows NT 10.0.16299.0",
        eol: "\r\n",
        signed: true,
    }
}

/// Its rebuild: a modern NuGet on Linux, unsigned, with its own fresh GUID and ids.
fn rebuilt() -> Pack<'static> {
    Pack {
        guid: "4f28fcb5c9304310a279a6ce74f94f55",
        rel_ids: ["R192ff84775f641df", "Rc0ffee00c0ffee00"],
        packer: "NuGet.Build.Tasks.Pack, Version=6.8.0.122;Unix 6.5.0.1;.NET 8.0.1",
        eol: "\n",
        signed: false,
    }
}

#[test]
fn two_packs_of_one_source_agree_once_packaging_bookkeeping_is_removed() {
    let (a, applied) = stabilize(&nupkg(), published().bytes());
    let (b, _) = stabilize(&nupkg(), rebuilt().bytes());
    assert!(
        a == b,
        "the packs still differ:\n{:#?}\n{:#?}",
        members(a),
        members(b)
    );
    for pass in [
        "nupkg-signature",
        "nupkg-packaging-names",
        "nupkg-packager-version",
        "nupkg-text-eol",
    ] {
        assert!(
            ids(&applied).contains(&pass),
            "`{pass}` did not fire: {:?}",
            ids(&applied)
        );
    }
}

#[test]
fn a_real_difference_in_the_package_still_shows() {
    let a = rebuilt().bytes();
    let b = {
        let mut m = members(a.clone());
        let n = m
            .iter_mut()
            .find(|(n, _)| n == "lib/net8.0/Demo.txt")
            .unwrap();
        n.1 = b"payload, changed\n".to_vec();
        let refs: Vec<(&str, &[u8])> = m.iter().map(|(n, b)| (n.as_str(), b.as_slice())).collect();
        zip(&refs)
    };
    assert!(stabilize(&nupkg(), a).0 != stabilize(&nupkg(), b).0);
}

#[test]
fn a_stabilized_package_stabilizes_to_itself() {
    let (once, _) = stabilize(&nupkg(), published().bytes());
    let (twice, again) = stabilize(&nupkg(), once.clone());
    assert!(once == twice);
    assert!(
        again.is_empty(),
        "work reported on a second pass: {:?}",
        ids(&again)
    );
}

// --- nupkg-packaging-names -----------------------------------------------------------------------

#[test]
fn the_core_properties_part_takes_its_canonical_name_and_remembers_the_real_one() {
    let mut notes: Vec<Note> = Vec::new();
    let mut p = parse(
        published().bytes(),
        Format::Zip,
        &Limits::default(),
        &mut notes,
    )
    .unwrap();
    apply(&only("nupkg-packaging-names"), &mut p.archive);
    let e = p
        .archive
        .entries
        .iter()
        .find(|e| e.path.as_bytes().ends_with(b".psmdcp"))
        .unwrap();
    assert_eq!(e.path.to_lossy(), CANONICAL_PSMDCP);
    // The comparison names members from the stabilized archive; a link back to the bytes needs
    // the name they are really under.
    assert!(e.was_renamed());
    assert_eq!(
        e.raw_path().to_lossy(),
        format!("{PSMDCP_DIR}55d4e0b4ecfa412baa282881ce747f48.psmdcp")
    );
}

#[test]
fn only_a_psmdcp_in_the_core_properties_folder_takes_the_canonical_name() {
    // The GUID-named part is one file in one folder. A `.psmdcp` the package ships elsewhere, or
    // another file beside the part, is named by its author and keeps that name.
    let other = format!("{PSMDCP_DIR}notes.txt");
    let bytes = zip(&[
        ("_rels/.rels", b"<Relationships/>"),
        (
            &format!("{PSMDCP_DIR}55d4e0b4.psmdcp"),
            b"<coreProperties/>",
        ),
        (&other, b"notes"),
        ("content/sample.psmdcp", b"<coreProperties/>"),
    ]);
    let (out, _) = stabilize(&only("nupkg-packaging-names"), bytes);
    let mut names: Vec<String> = members(out).into_iter().map(|(n, _)| n).collect();
    names.sort();
    assert_eq!(
        names,
        [
            "_rels/.rels",
            "content/sample.psmdcp",
            CANONICAL_PSMDCP,
            other.as_str()
        ]
    );
}

#[test]
fn the_relationships_part_points_at_the_canonical_name_with_positional_ids() {
    let (out, _) = stabilize(&only("nupkg-packaging-names"), published().bytes());
    let rels = member(out, "_rels/.rels");
    assert!(
        rels.contains(&format!("Target=\"/{CANONICAL_PSMDCP}\" Id=\"R1\"")),
        "the core-properties target: {rels}"
    );
    // The other relationship keeps its target, and the two keep distinct ids rather than
    // collapsing onto one.
    assert!(rels.contains("Target=\"/Demo.nuspec\" Id=\"R0\""), "{rels}");
    assert!(
        !rels.contains("R2BEFEA914E60C8DE") && !rels.contains("55d4e0b4"),
        "{rels}"
    );
}

#[test]
fn a_package_already_in_canonical_form_is_not_claimed() {
    let (once, _) = stabilize(&only("nupkg-packaging-names"), rebuilt().bytes());
    let (twice, applied) = stabilize(&only("nupkg-packaging-names"), once.clone());
    assert!(once == twice);
    assert!(applied.is_empty(), "{applied:?}");
}

#[test]
fn a_zip_with_no_relationships_part_is_not_an_opc_package() {
    // A wheel or a jar that happens to hold a path shaped like one is not renamed on the strength
    // of a suffix.
    let name = format!("{PSMDCP_DIR}55d4e0b4ecfa412baa282881ce747f48.psmdcp");
    let bytes = zip(&[(name.as_str(), b"<coreProperties/>"), ("x.py", b"")]);
    let (out, applied) = stabilize(&only("nupkg-packaging-names"), bytes);
    assert!(applied.is_empty(), "{applied:?}");
    assert!(members(out).iter().any(|(n, _)| *n == name));
}

#[test]
fn a_relationships_part_cut_off_mid_attribute_is_copied_not_guessed_at() {
    // An unterminated value has no end to replace up to, so its bytes go through as they are.
    let rels = b"<Relationship Id=\"Rabc\" Target=\"/x.psmdcp".as_slice();
    let (out, _) = stabilize(
        &only("nupkg-packaging-names"),
        zip(&[("_rels/.rels", rels)]),
    );
    assert_eq!(
        member(out, "_rels/.rels"),
        "<Relationship Id=\"R0\" Target=\"/x.psmdcp"
    );

    let rels = format!("<Relationship Target=\"/{PSMDCP_DIR}abc.psmdcp\" Id=\"Rabc");
    let (out, _) = stabilize(
        &only("nupkg-packaging-names"),
        zip(&[("_rels/.rels", rels.as_bytes())]),
    );
    assert_eq!(
        member(out, "_rels/.rels"),
        format!("<Relationship Target=\"/{CANONICAL_PSMDCP}\" Id=\"Rabc")
    );
}

// --- nupkg-packager-version ----------------------------------------------------------------------

#[test]
fn the_packing_tool_and_machine_are_dropped_from_core_properties() {
    let (out, applied) = stabilize(&only("nupkg-packager-version"), rebuilt().bytes());
    let name = format!("{PSMDCP_DIR}4f28fcb5c9304310a279a6ce74f94f55.psmdcp");
    let core = member(out, &name);
    assert!(core.contains("<lastModifiedBy></lastModifiedBy>"), "{core}");
    assert!(
        core.contains("<dc:creator>Demo</dc:creator>"),
        "the rest is kept: {core}"
    );
    let [a] = applied.as_slice() else {
        panic!("{applied:?}")
    };
    assert_eq!(a.risk, RiskTier::Metadata);
    assert_eq!(a.bytes_changed as usize, rebuilt().packer.len());
}

#[test]
fn core_properties_with_nothing_to_drop_are_not_claimed() {
    for core in [
        "<coreProperties><lastModifiedBy></lastModifiedBy></coreProperties>",
        "<coreProperties><version>1.0.0</version></coreProperties>",
        // Opened and never closed: there is no end to cut to.
        "<coreProperties><lastModifiedBy>NuGet 6.8",
    ] {
        let bytes = zip(&[(CANONICAL_PSMDCP, core.as_bytes())]);
        let (out, applied) = stabilize(&only("nupkg-packager-version"), bytes);
        assert!(applied.is_empty(), "{core}: {applied:?}");
        assert_eq!(member(out, CANONICAL_PSMDCP), core);
    }
}

#[test]
fn a_last_modified_by_outside_core_properties_is_content() {
    let doc = "<doc><lastModifiedBy>the author</lastModifiedBy></doc>";
    let bytes = zip(&[("lib/net8.0/Demo.xml", doc.as_bytes())]);
    let (out, applied) = stabilize(&only("nupkg-packager-version"), bytes);
    assert!(applied.is_empty(), "{applied:?}");
    assert_eq!(member(out, "lib/net8.0/Demo.xml"), doc);
}

// --- nupkg-signature -----------------------------------------------------------------------------

#[test]
fn only_the_gallerys_own_signature_is_dropped() {
    // The countersignature nuget.org adds sits at the root. A package that ships a file of that
    // name further in is shipping it, and dropping it from both sides would hide a difference —
    // the gem `.sig` false match, again.
    let a = zip(&[
        (".signature.p7s", b"gallery A"),
        ("content/.signature.p7s", b"the package's own, one"),
    ]);
    let b = zip(&[
        (".signature.p7s", b"gallery B"),
        ("content/.signature.p7s", b"the package's own, two"),
    ]);
    let (sa, applied) = stabilize(&only("nupkg-signature"), a);
    let (sb, _) = stabilize(&only("nupkg-signature"), b);
    assert!(
        sa != sb,
        "a shipped `.signature.p7s` was dropped from both sides"
    );
    let names: Vec<String> = members(sa).into_iter().map(|(n, _)| n).collect();
    assert_eq!(names, ["content/.signature.p7s"]);
    assert_eq!(applied[0].risk, RiskTier::Structural);
}

// --- nupkg-text-eol ------------------------------------------------------------------------------

#[test]
fn text_members_lose_carriage_returns_before_line_feeds_only() {
    let bytes = zip(&[
        ("Demo.nuspec", b"<package>\r\n</package>\r\n"),
        ("docs/notes.txt", b"one\r\ntwo\rthree\n"),
        ("lib/net8.0/Demo.dll", b"MZ\r\n\x00\x00binary\r\n"),
        ("tools/install.ps1", b"Write-Host hi\r\n"),
    ]);
    let (out, applied) = stabilize(&only("nupkg-text-eol"), bytes);
    assert_eq!(
        member(out.clone(), "Demo.nuspec"),
        "<package>\n</package>\n"
    );
    // A lone CR is a classic-Mac line ending and content, not a CRLF spelled differently.
    assert_eq!(member(out.clone(), "docs/notes.txt"), "one\ntwo\rthree\n");
    // By extension, never by sniffing: an assembly or a script keeps every byte.
    let m = members(out);
    let dll = &m
        .iter()
        .find(|(n, _)| n == "lib/net8.0/Demo.dll")
        .unwrap()
        .1;
    assert_eq!(dll, b"MZ\r\n\x00\x00binary\r\n");
    let ps1 = &m.iter().find(|(n, _)| n == "tools/install.ps1").unwrap().1;
    assert_eq!(ps1, b"Write-Host hi\r\n");

    let [a] = applied.as_slice() else {
        panic!("{applied:?}")
    };
    assert_eq!(
        (a.entries_touched, a.bytes_changed),
        (2, 3),
        "two members, three CRs"
    );
    assert_eq!(a.risk, RiskTier::Content, "bytes a consumer receives");
}

#[test]
fn a_text_member_already_in_lf_is_not_claimed() {
    let bytes = zip(&[
        ("Demo.nuspec", b"<package>\n</package>\n"),
        ("x.md", b"a\rb"),
    ]);
    let (_, applied) = stabilize(&only("nupkg-text-eol"), bytes);
    assert!(applied.is_empty(), "{applied:?}");
}

#[test]
fn a_tarball_the_package_ships_is_not_a_package_member() {
    // `apply` visits every archive depth, so a `.tar.gz` the package ships is parsed and walked
    // too. The text inside it has the line endings its author gave it, not the packing machine's,
    // and the passes written for the zip NuGet writes leave it alone.
    let shipped = |readme: &[u8]| {
        use std::io::Write as _;
        let mut b = ::tar::Builder::new(Vec::new());
        let mut h = ::tar::Header::new_ustar();
        h.set_size(readme.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, "sample/readme.txt", readme).unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&b.into_inner().unwrap()).unwrap();
        gz.finish().unwrap()
    };
    let package = |readme: &[u8]| {
        zip(&[
            ("Demo.nuspec", b"<package/>\n"),
            ("content/sample.tar.gz", &shipped(readme)),
        ])
    };
    let (crlf, applied) = stabilize(&nupkg(), package(b"one\r\ntwo\r\n"));
    let (lf, _) = stabilize(&nupkg(), package(b"one\ntwo\n"));
    assert_ne!(
        crlf, lf,
        "a difference inside a shipped tarball is a difference"
    );
    assert!(!ids(&applied).contains(&"nupkg-text-eol"), "{applied:?}");
}

// --- nupkg-doc-member-order-v2 -------------------------------------------------------------------

fn doc(members: &[&str]) -> Vec<u8> {
    let mut d =
        "<?xml version=\"1.0\"?>\n<doc>\n<assembly><name>Demo</name></assembly>\n<members>\n"
            .to_string();
    for m in members {
        d.push_str(m);
        d.push('\n');
    }
    d.push_str("</members>\n</doc>\n");
    d.into_bytes()
}

#[test]
fn two_collations_of_one_doc_file_agree() {
    // Windows and ICU disagree about where `.` sorts, so one source writes one set of elements in
    // two orders.
    let x = "<member name=\"M:Demo.X.Run\">\n<summary>runs</summary>\n</member>";
    let y = "<member name=\"M:Demo.X_Y.Run\">\n<summary>also</summary>\n</member>";
    let t = "<member name=\"T:Demo.X\">\n<summary>a type</summary>\n</member>";
    let a = zip(&[("lib/net8.0/Demo.xml", &doc(&[x, y, t]))]);
    let b = zip(&[("lib/net8.0/Demo.xml", &doc(&[y, x, t]))]);
    let (sa, already) = stabilize(&only("nupkg-doc-member-order-v2"), a);
    let (sb, applied) = stabilize(&only("nupkg-doc-member-order-v2"), b);
    assert_eq!(
        member(sa, "lib/net8.0/Demo.xml"),
        member(sb, "lib/net8.0/Demo.xml")
    );
    assert!(
        already.is_empty(),
        "the order already sorted was claimed: {already:?}"
    );
    assert_eq!(ids(&applied), ["nupkg-doc-member-order-v2"]);
    assert_eq!(applied[0].risk, RiskTier::Structural);
}

#[test]
fn sorting_loses_no_member_and_changes_no_text() {
    // A member without a `name` has nothing to sort by; it still has to come out the other side,
    // along with every body, and only the order may change.
    let blocks = [
        "<member name=\"T:B\">\n<summary>bee</summary>\n</member>",
        "<member cref=\"x\">\n<summary>unnamed</summary>\n</member>",
        "<member name=\"T:A\">\n<summary>ay</summary>\n</member>",
    ];
    let (out, _) = stabilize(
        &only("nupkg-doc-member-order-v2"),
        zip(&[("lib/net8.0/Demo.xml", &doc(&blocks))]),
    );
    let text = member(out, "lib/net8.0/Demo.xml");
    for b in blocks {
        assert_eq!(
            text.matches(b).count(),
            1,
            "`{b}` did not survive exactly once:\n{text}"
        );
    }
    assert!(
        text.find("T:A").unwrap() < text.find("T:B").unwrap(),
        "{text}"
    );
    let mut before = doc(&blocks);
    let mut after = text.into_bytes();
    before.sort_unstable();
    after.sort_unstable();
    assert_eq!(
        before, after,
        "sorting is a permutation of the document's bytes"
    );
}

#[test]
fn only_generated_documentation_beside_an_assembly_is_reordered() {
    let unsorted = doc(&["<member name=\"T:B\"/>", "<member name=\"T:A\"/>"]);
    for name in [
        "docs/Demo.xml",
        "[Content_Types].xml",
        "lib/net8.0/Demo.txt",
    ] {
        let (out, applied) = stabilize(
            &only("nupkg-doc-member-order-v2"),
            zip(&[(name, &unsorted)]),
        );
        assert!(applied.is_empty(), "`{name}`: {applied:?}");
        assert_eq!(
            member(out, name).into_bytes(),
            unsorted,
            "`{name}` was reordered"
        );
    }
}

#[test]
fn a_members_element_closed_before_it_opens_is_not_rewritten() {
    let d = b"<doc></members><members><member name=\"T:B\"/><member name=\"T:A\"/>".as_slice();
    let (out, applied) = stabilize(
        &only("nupkg-doc-member-order-v2"),
        zip(&[("lib/Demo.xml", d)]),
    );
    assert!(applied.is_empty(), "{applied:?}");
    assert_eq!(member(out, "lib/Demo.xml").as_bytes(), d);
}

// --- nupkg-repository-branch ---------------------------------------------------------------------

fn nuspec(repository: &str) -> Vec<u8> {
    format!(
        "<package>\n<metadata>\n<id>Moq</id>\n{repository}\n\
         <dependencies><dependency id=\"Castle.Core\" version=\"5.1.1\" /></dependencies>\n\
         </metadata>\n</package>\n"
    )
    .into_bytes()
}

#[test]
fn the_ref_a_publisher_built_from_is_dropped_and_the_commit_kept() {
    // moq@4.20.72's nuspec differed in exactly this: the publisher built from the tag, trigon
    // checks the same commit out detached.
    let with = nuspec(
        "<repository type=\"git\" url=\"https://github.com/devlooped/moq\" branch=\"v4.20.72\" \
         commit=\"26d6a4d\" />",
    );
    let without = nuspec(
        "<repository type=\"git\" url=\"https://github.com/devlooped/moq\" commit=\"26d6a4d\" />",
    );
    let (a, applied) = stabilize(
        &only("nupkg-repository-branch"),
        zip(&[("Moq.nuspec", &with)]),
    );
    let (b, none) = stabilize(
        &only("nupkg-repository-branch"),
        zip(&[("Moq.nuspec", &without)]),
    );
    assert_eq!(member(a.clone(), "Moq.nuspec"), member(b, "Moq.nuspec"));
    assert!(member(a, "Moq.nuspec").contains("commit=\"26d6a4d\""));
    assert_eq!(applied[0].risk, RiskTier::Metadata);
    assert!(
        none.is_empty(),
        "a nuspec with no branch was claimed: {none:?}"
    );
}

#[test]
fn a_different_commit_still_shows() {
    let a = nuspec("<repository type=\"git\" branch=\"main\" commit=\"26d6a4d\" />");
    let b = nuspec("<repository type=\"git\" branch=\"main\" commit=\"0badc0d\" />");
    let (sa, _) = stabilize(&only("nupkg-repository-branch"), zip(&[("Moq.nuspec", &a)]));
    let (sb, _) = stabilize(&only("nupkg-repository-branch"), zip(&[("Moq.nuspec", &b)]));
    assert!(sa != sb);
}

#[test]
fn a_branch_attribute_anywhere_but_the_repository_element_is_kept() {
    for spec in [
        // On another element entirely.
        nuspec("<repository type=\"git\" commit=\"26d6a4d\" /><x branch=\"keep\" />"),
        // No repository element at all.
        nuspec("<projectUrl branch=\"keep\">https://example.org</projectUrl>"),
        // A repository element that never closes.
        b"<package><repository branch=\"keep\"".to_vec(),
    ] {
        let (out, applied) = stabilize(
            &only("nupkg-repository-branch"),
            zip(&[("Moq.nuspec", &spec)]),
        );
        assert!(applied.is_empty(), "{applied:?}");
        assert_eq!(member(out, "Moq.nuspec").into_bytes(), spec);
    }
    // And only a `.nuspec` is read for it.
    let other = nuspec("<repository branch=\"v1\" />");
    let (_, applied) = stabilize(&only("nupkg-repository-branch"), zip(&[("x.xml", &other)]));
    assert!(applied.is_empty(), "{applied:?}");
}

// --- nupkg-readme-markers ------------------------------------------------------------------------

#[test]
fn nugetizer_markers_and_the_blanks_they_leave_are_normalized_away() {
    // The publisher's networked build and trigon's mirror-only one spell the markers around an
    // include differently; the included text itself is the same (docs/16-findings.md §3.86).
    let publisher = "# Moq\n\n<!-- include ../../readme.md#content -->\nThe mocking library.  \n\
                     <!-- #content -->\n\n\n\
                     <!-- include https://github.com/devlooped/sponsors/raw/main/footer.md -->\n\
                     Sponsored by the people below.\n\
                     <!-- https://github.com/devlooped/sponsors/raw/main/footer.md -->\n";
    let rebuild = "# Moq\n\nThe mocking library.\n\nSponsored by the people below.\n";
    let (a, applied) = stabilize(
        &only("nupkg-readme-markers"),
        zip(&[("readme.md", publisher.as_bytes())]),
    );
    let (b, _) = stabilize(
        &only("nupkg-readme-markers"),
        zip(&[("readme.md", rebuild.as_bytes())]),
    );
    assert_eq!(member(a.clone(), "readme.md"), rebuild);
    assert_eq!(member(b, "readme.md"), rebuild);
    assert_eq!(applied[0].risk, RiskTier::Content);
}

#[test]
fn a_prose_comment_is_not_a_marker() {
    // A comment with words in it is the author's, and a reader of the source sees it.
    let md = "# Demo\n<!-- do not edit: generated from the wiki -->\n<!-- -->\ntext\n";
    let (out, applied) = stabilize(
        &only("nupkg-readme-markers"),
        zip(&[("README.md", md.as_bytes())]),
    );
    assert_eq!(member(out, "README.md"), md);
    assert!(applied.is_empty(), "{applied:?}");
}

#[test]
fn a_readme_with_nothing_to_normalize_is_not_claimed() {
    // The common case: a readme ending in a newline, no markers, no trailing blanks. Claiming it
    // puts a `Content` pass in `applied`, and a pass in `applied` is what caps a verdict below
    // `normalized` — for a file the pass left byte for byte as it was.
    for md in ["# Demo\n\nSome text.\n", "no trailing newline", ""] {
        let (out, applied) = stabilize(
            &only("nupkg-readme-markers"),
            zip(&[("README.md", md.as_bytes())]),
        );
        assert!(
            applied.is_empty(),
            "{md:?} was claimed unchanged: {applied:?}"
        );
        assert_eq!(member(out, "README.md"), md);
    }
}

#[test]
fn only_markdown_is_read_for_markers() {
    let txt = "<!-- include footer.md -->\ntext\n";
    let (out, applied) = stabilize(
        &only("nupkg-readme-markers"),
        zip(&[("notes.txt", txt.as_bytes())]),
    );
    assert!(applied.is_empty(), "{applied:?}");
    assert_eq!(member(out, "notes.txt"), txt);
}

// --- nupkg-portable-folder-name ------------------------------------------------------------------

#[test]
fn a_portable_profile_folder_is_renamed_and_a_portable_file_is_not() {
    let bytes = zip(&[
        ("lib/portable-net45%2Bwin8/Demo.dll", b"a"),
        // A file directly under lib/ has no framework segment to rename.
        ("lib/portable45-net45+win8", b"b"),
        // Nor does a path outside lib/.
        ("ref/portable45-net45+win8/Demo.dll", b"c"),
    ]);
    let (out, _) = stabilize(&only("nupkg-portable-folder-name"), bytes);
    let mut names: Vec<String> = members(out).into_iter().map(|(n, _)| n).collect();
    names.sort();
    assert_eq!(
        names,
        [
            "lib/portable-net45+win8/Demo.dll",
            "lib/portable45-net45+win8",
            "ref/portable45-net45+win8/Demo.dll"
        ]
    );
}

#[test]
fn a_percent_encoded_plus_is_decoded_in_either_case_and_a_cut_off_escape_is_left() {
    // `%2B` and `%2b` are one escape. A `%2` at the very end is no escape at all: it is kept as
    // written, and the rest of the name is still canonicalized.
    let bytes = zip(&[
        ("lib/portable-net45%2bwin8/Demo.dll", b"a"),
        ("lib/portable45-net45+win8%2/Demo.dll", b"b"),
    ]);
    let (out, _) = stabilize(&only("nupkg-portable-folder-name"), bytes);
    let mut names: Vec<String> = members(out).into_iter().map(|(n, _)| n).collect();
    names.sort();
    assert_eq!(
        names,
        [
            "lib/portable-net45+win8%2/Demo.dll",
            "lib/portable-net45+win8/Demo.dll"
        ]
    );
}
