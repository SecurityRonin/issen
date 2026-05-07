//! PDF export for `Issen` HTML reports.
//!
//! Converts an HTML report string to a minimal single-page PDF by stripping
//! HTML tags and writing the plain text with `printpdf` using a built-in font.
//! No external binaries or system dependencies are required.

use std::path::Path;

use printpdf::{BuiltinFont, Mm, Op, PdfDocument, PdfFontHandle, PdfPage, PdfSaveOptions, Pt, TextItem};

/// Export an HTML string as a PDF file at `output_path`.
///
/// HTML tags are stripped to plain text before writing. The output is a valid
/// PDF document using Helvetica (a PDF built-in font), so no font files
/// need to be shipped alongside the binary.
///
/// # Errors
///
/// Returns an error if `output_path` cannot be written, or if PDF generation
/// fails internally.
pub fn expoissen_pdf(html: &str, output_path: &Path) -> anyhow::Result<()> {
    let plain_text = strip_html(html);
    let lines: Vec<&str> = plain_text.lines().collect();

    let mut doc = PdfDocument::new("Issen Report");

    let font = PdfFontHandle::Builtin(BuiltinFont::Helvetica);

    // Build text operations for the page.
    let mut ops = vec![
        Op::StartTextSection,
        Op::SetFont {
            font: font.clone(),
            size: Pt(11.0),
        },
        Op::SetLineHeight { lh: Pt(14.0) },
        // Position text at top-left with a reasonable margin (A4: 210×297 mm).
        Op::SetTextCursor {
            pos: printpdf::Point {
                x: Mm(15.0).into(),
                y: Mm(277.0).into(),
            },
        },
    ];

    if lines.is_empty() {
        // Emit an empty text item so the page is still valid.
        ops.push(Op::ShowText {
            items: vec![TextItem::Text(String::new())],
        });
    } else {
        for line in &lines {
            ops.push(Op::ShowText {
                items: vec![TextItem::Text((*line).to_string())],
            });
            ops.push(Op::AddLineBreak);
        }
    }

    ops.push(Op::EndTextSection);

    // A4 page: 210 × 297 mm.
    let page = PdfPage::new(Mm(210.0), Mm(297.0), ops);

    let save_options = PdfSaveOptions::default();
    let mut warnings = Vec::new();
    let pdf_bytes = doc.with_pages(vec![page]).save(&save_options, &mut warnings);

    std::fs::write(output_path, pdf_bytes)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Strip HTML tags from a string, returning plain text.
///
/// Uses a simple state-machine char-walk — no regex dependency needed.
fn strip_html(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut in_tag = false;

    for ch in html.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                // Emit a space so words adjacent to tags don't merge.
                result.push(' ');
            }
            _ if !in_tag => result.push(ch),
            _ => {}
        }
    }

    // Collapse multiple blank lines and trim trailing whitespace per line.
    let mut out = String::with_capacity(result.len());
    let mut blank_run = 0u32;
    for line in result.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            blank_run += 1;
            if blank_run <= 1 {
                out.push('\n');
            }
        } else {
            blank_run = 0;
            out.push_str(trimmed);
            out.push('\n');
        }
    }

    out
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    const SIMPLE_HTML: &str = r#"<!DOCTYPE html>
<html><head><title>Test Report</title></head>
<body><h1>Issen Report</h1>
<p>Event count: <strong>42</strong></p>
</body></html>"#;

    /// `expoissen_pdf` must create a non-empty file at the given path.
    #[test]
    fn expoissen_pdf_creates_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("report.pdf");

        expoissen_pdf(SIMPLE_HTML, &out).expect("expoissen_pdf should succeed");

        assert!(out.exists(), "output file should exist after expoissen_pdf");
        let meta = std::fs::metadata(&out).expect("metadata");
        assert!(meta.len() > 0, "output file should be non-empty");
    }

    /// The first four bytes of a valid PDF must be `%PDF`.
    #[test]
    fn expoissen_pdf_file_starts_with_pdf_magic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("report.pdf");

        expoissen_pdf(SIMPLE_HTML, &out).expect("expoissen_pdf should succeed");

        let mut f = std::fs::File::open(&out).expect("open output");
        let mut magic = [0u8; 4];
        f.read_exact(&mut magic).expect("read magic bytes");
        asseissen_eq!(&magic, b"%PDF", "file must start with PDF magic bytes");
    }

    /// Calling `expoissen_pdf` with an empty HTML string must not panic.
    #[test]
    fn expoissen_pdf_empty_html_succeeds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("empty.pdf");

        expoissen_pdf("", &out).expect("expoissen_pdf with empty html should succeed");

        assert!(out.exists(), "output file should exist for empty html input");
    }
}
