//! The in-memory table every batch operation works on.

/// A header and its rows, every cell a string — exactly what the CSV flow
/// reads and writes, so one implementation serves the command line (which
/// fills it from chunk files) and library callers (which fill it from Arrow
/// record batches, see the `arrow` feature).
///
/// Cells are strings on purpose: SKALD reads a quasi-identifier through
/// `parse_numeric_qi` / `normalize_categorical` and an identifier through
/// `normalize_identifier`, whatever type the source column had, and an empty
/// cell is the one missing-value marker. Keeping that single reading in one
/// place is what makes a batch result equal the file result.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Table {
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
    /// Where the rows came from (a chunk path, a batch number). Used in error
    /// messages only — never a value from the data.
    pub source: String,
}

impl Table {
    /// Reads a whole CSV file (every row as wide as its header).
    pub fn from_csv_file(path: &std::path::Path) -> Result<Self, crate::pipeline::bootstrap::PipelineError> {
        let (headers, mut records) = crate::pipeline::bootstrap::open_csv(path)?;
        let mut rows = Vec::new();
        while let Some(fields) = records.next_record_of_width(headers.len())? {
            rows.push(fields);
        }
        Ok(Self::new(headers, rows, path.display().to_string()))
    }

    pub fn new(headers: Vec<String>, rows: Vec<Vec<String>>, source: impl Into<String>) -> Self {
        Self { headers, rows, source: source.into() }
    }

    /// Index of the column named `name`, by exact match.
    pub fn column(&self, name: &str) -> Option<usize> {
        self.headers.iter().position(|h| h == name)
    }
}
