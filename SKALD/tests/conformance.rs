//! Runs the command line over every case in `conformance/cases` and compares
//! what it writes with `conformance/expected`, which was recorded from the
//! 4.1.0 build before the batch API existed. A refactor that changes any
//! output byte fails here.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("conformance")
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for e in fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dest = to.join(e.file_name());
        if e.path().is_dir() {
            copy_dir(&e.path(), &dest);
        } else {
            fs::copy(e.path(), dest).unwrap();
        }
    }
}

/// status.json without the parts that differ between hosts and runs.
fn normalised_status(raw: &str, root: &Path) -> Value {
    let text = raw.replace(&root.display().to_string(), "<ROOT>");
    let mut v: Value = serde_json::from_str(&text).unwrap();
    if let Some(o) = v.get_mut("outputs").and_then(Value::as_object_mut) {
        o.remove("rows_per_chunk");
    }
    v
}

#[test]
fn the_command_line_reproduces_every_recorded_output() {
    let mut cases: Vec<_> = fs::read_dir(corpus().join("cases")).unwrap().map(|e| e.unwrap().file_name()).collect();
    cases.sort();
    assert!(cases.len() >= 8, "the corpus is missing");
    for case in cases {
        let case = case.to_string_lossy().to_string();
        let work = std::env::temp_dir().join(format!("skald_conf_{case}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&work);
        fs::create_dir_all(work.join("data")).unwrap();
        fs::create_dir_all(work.join("config")).unwrap();
        let src = corpus().join("cases").join(&case);
        // One CSV, or (the join cases) one workbook.
        for data in ["data.csv", "data.xlsx"] {
            if src.join(data).exists() {
                fs::copy(src.join(data), work.join("data").join(data)).unwrap();
            }
        }
        fs::copy(src.join("config.json"), work.join("config/config.json")).unwrap();
        copy_dir(&src.join("testkeys"), &work.join("keys"));

        let status = Command::new(env!("CARGO_BIN_EXE_skald_pipeline")).arg("--root").arg(&work).output().unwrap();
        assert!(status.status.success(), "{case}: exit {:?}", status.status.code());

        let expected = corpus().join("expected").join(&case);
        for e in fs::read_dir(&expected).unwrap() {
            let name = e.unwrap().file_name().to_string_lossy().to_string();
            let want = fs::read_to_string(expected.join(&name)).unwrap();
            // `sheet.<name>.csv` is one sheet of the workbook `restore_sheets` writes, as CSV.
            if let Some(sheet) = name.strip_prefix("sheet.").and_then(|n| n.strip_suffix(".csv")) {
                let book = skald_ola2::pipeline::multitabular::read_xlsx_sheets(&work.join("output/anonymized.xlsx"))
                    .unwrap_or_else(|e| panic!("{case}: restored workbook: {e}"));
                let (_, restored) =
                    book.into_iter().find(|(n, _)| n == sheet).unwrap_or_else(|| panic!("{case}: no sheet {sheet}"));
                let mut got = String::new();
                for row in std::iter::once(&restored.columns).chain(restored.rows.iter()) {
                    got.push_str(&skald_ola2::pipeline::bootstrap::csv_row_to_line(row));
                    got.push('\n');
                }
                assert_eq!(got, want, "{case}: sheet {sheet}");
                continue;
            }
            let got =
                fs::read_to_string(work.join("output").join(&name)).unwrap_or_else(|_| panic!("{case}: no {name}"));
            if name == "status.json" {
                assert_eq!(normalised_status(&got, &work), normalised_status(&want, &work), "{case}: status.json");
            } else {
                assert_eq!(got, want, "{case}: {name}");
            }
        }
        let _ = fs::remove_dir_all(&work);
    }
}
