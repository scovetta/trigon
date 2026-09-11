//! Filtering a PyPI simple index to a moment.
//!
//! The upstream request is always for the **JSON** simple API, whatever the client asked for. The
//! HTML form carries no upload times at all, so it cannot be filtered by date: a mirror that
//! proxied HTML would pass every file through and quietly do nothing. Where the client wanted HTML
//! it is rendered back from the filtered JSON.

use serde_json::Value;

use crate::moment::published_by;

/// Filter a simple-API document in place. Returns how many files were removed.
pub fn filter_simple(doc: &mut Value, moment: &str) -> usize {
    let Some(files) = doc.get_mut("files").and_then(Value::as_array_mut) else {
        return 0;
    };
    let before = files.len();
    files.retain(|f| {
        // `upload-time` is the simple API's spelling; the JSON project API uses
        // `upload_time_iso_8601`. A file with neither cannot be dated and is excluded.
        match f
            .get("upload-time")
            .or_else(|| f.get("upload_time_iso_8601"))
            .and_then(Value::as_str)
        {
            Some(ts) => published_by(ts, moment),
            None => false,
        }
    });
    before - files.len()
}

/// Render a filtered simple-API document as PEP 503 HTML.
///
/// For clients that asked for HTML. Only the anchor list matters to a resolver: the filename is
/// its text and the hash rides in the fragment.
pub fn render_html(doc: &Value, project: &str) -> String {
    let mut out = String::from("<!DOCTYPE html><html><head><meta charset=\"utf-8\">");
    out.push_str(&format!("<title>Links for {project}</title></head><body>"));
    out.push_str(&format!("<h1>Links for {project}</h1>"));
    for f in doc
        .get("files")
        .and_then(Value::as_array)
        .unwrap_or(&vec![])
    {
        let (Some(name), Some(url)) = (
            f.get("filename").and_then(Value::as_str),
            f.get("url").and_then(Value::as_str),
        ) else {
            continue;
        };
        let hash = f
            .get("hashes")
            .and_then(|h| h.get("sha256"))
            .and_then(Value::as_str)
            .map(|h| format!("#sha256={h}"))
            .unwrap_or_default();
        let requires = f
            .get("requires-python")
            .and_then(Value::as_str)
            .map(|r| format!(" data-requires-python=\"{}\"", escape(r)))
            .unwrap_or_default();
        out.push_str(&format!(
            "<a href=\"{}{hash}\"{requires}>{}</a><br/>",
            escape(url),
            escape(name)
        ));
    }
    out.push_str("</body></html>");
    out
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple() -> Value {
        serde_json::json!({
            "name": "demo",
            "files": [
                {"filename": "demo-1.0.tar.gz", "url": "https://files/demo-1.0.tar.gz",
                 "upload-time": "2018-01-01T00:00:00.000000Z",
                 "hashes": {"sha256": "aaa"}},
                {"filename": "demo-2.0-py3-none-any.whl", "url": "https://files/demo-2.0.whl",
                 "upload-time": "2020-06-01T12:00:00.000000Z",
                 "hashes": {"sha256": "bbb"}}
            ],
            "meta": {"api-version": "1.0"}
        })
    }

    #[test]
    fn files_uploaded_later_are_removed() {
        let mut d = simple();
        assert_eq!(filter_simple(&mut d, "2019-01-01T00:00:00"), 1);
        let files = d["files"].as_array().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0]["filename"], "demo-1.0.tar.gz");
    }

    #[test]
    fn a_file_with_no_upload_time_is_excluded() {
        let mut d = simple();
        d["files"].as_array_mut().unwrap().push(serde_json::json!({
            "filename": "demo-3.0.whl", "url": "https://files/demo-3.0.whl"
        }));
        filter_simple(&mut d, "2025-01-01T00:00:00");
        assert!(
            !d["files"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["filename"] == "demo-3.0.whl"),
            "a file we cannot date must not be resolvable"
        );
    }

    #[test]
    fn html_is_rendered_from_the_filtered_json() {
        // The HTML simple API carries no upload times, so it cannot be filtered directly. A mirror
        // that proxied it would pass every file through and quietly do nothing.
        let mut d = simple();
        filter_simple(&mut d, "2019-01-01T00:00:00");
        let html = render_html(&d, "demo");
        assert!(html.contains("demo-1.0.tar.gz"), "{html}");
        assert!(
            !html.contains("demo-2.0"),
            "the filtered file must not reappear: {html}"
        );
        assert!(html.contains("#sha256=aaa"), "{html}");
    }

    #[test]
    fn html_escapes_what_it_interpolates() {
        let d = serde_json::json!({"files": [
            {"filename": "a<b>.whl", "url": "https://x/a?q=1&r=2", "hashes": {}}
        ]});
        let html = render_html(&d, "demo");
        assert!(html.contains("a&lt;b&gt;.whl"), "{html}");
        assert!(html.contains("q=1&amp;r=2"), "{html}");
    }
}
