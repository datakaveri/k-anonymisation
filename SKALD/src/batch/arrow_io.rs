//! Arrow record batches in and out of [`Table`].
//!
//! Every column is read as text, whatever its Arrow type: SKALD reads a
//! quasi-identifier through `parse_numeric_qi` and an identifier through
//! `normalize_identifier` regardless of the type the source had, so one rule
//! serves all inputs. A null cell becomes the empty string, which is the one
//! missing-value marker the techniques skip; output columns are `Utf8` and a
//! missing value is written as the empty string, not as null.
//!
//! Identifiers that were numbers upstream (an Aadhaar held as `int64`) should
//! be cast to string by the caller before hashing, so the digits that are
//! hashed are the digits the caller means. Arrow's own cast renders the rest:
//! an integer without a decimal point, a float as Arrow prints it (`2.0`).

use super::table::Table;
use crate::pipeline::bootstrap::{PipelineError, validation};
use arrow_array::{Array, ArrayRef, RecordBatch, StringArray, cast::AsArray};
use arrow_cast::cast;
use arrow_schema::{DataType, Field, Schema};
use std::sync::Arc;

fn arrow_err(what: &str, e: impl std::fmt::Display) -> PipelineError {
    validation("ARROW_CONVERSION_FAILED", what, &e.to_string())
}

/// Reads a record batch as a table of strings. `source` labels error messages.
///
/// # Errors
/// `ARROW_CONVERSION_FAILED` for a column type Arrow cannot render as text.
pub fn table_from_batch(batch: &RecordBatch, source: &str) -> Result<Table, PipelineError> {
    let schema = batch.schema();
    let headers: Vec<String> = schema.fields().iter().map(|f| f.name().clone()).collect();
    let n = batch.num_rows();
    let mut rows: Vec<Vec<String>> = (0..n).map(|_| Vec::with_capacity(headers.len())).collect();
    for (col, field) in batch.columns().iter().zip(schema.fields()) {
        let text: ArrayRef = if *col.data_type() == DataType::Utf8 {
            Arc::clone(col)
        } else {
            cast(col, &DataType::Utf8)
                .map_err(|e| arrow_err(&format!("column {} cannot be read as text", field.name()), e))?
        };
        let strings = text.as_string::<i32>();
        for (row, i) in rows.iter_mut().zip(0..n) {
            row.push(if strings.is_null(i) { String::new() } else { strings.value(i).to_string() });
        }
    }
    Ok(Table::new(headers, rows, source))
}

/// Writes a table as a record batch of `Utf8` columns.
///
/// # Errors
/// `ARROW_CONVERSION_FAILED` for rows of unequal width.
pub fn batch_from_table(table: &Table) -> Result<RecordBatch, PipelineError> {
    let fields: Vec<Field> = table.headers.iter().map(|h| Field::new(h, DataType::Utf8, true)).collect();
    let columns: Vec<ArrayRef> = (0..table.headers.len())
        .map(|c| Arc::new(StringArray::from_iter_values(table.rows.iter().map(|r| r[c].as_str()))) as ArrayRef)
        .collect();
    if table.rows.iter().any(|r| r.len() != table.headers.len()) {
        return Err(arrow_err("A row is not as wide as the header", &table.source));
    }
    RecordBatch::try_new_with_options(
        Arc::new(Schema::new(fields)),
        columns,
        &arrow_array::RecordBatchOptions::new().with_row_count(Some(table.rows.len())),
    )
    .map_err(|e| arrow_err("The table could not be written as a record batch", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow_array::{Float64Array, Int64Array};

    #[test]
    fn any_column_type_reads_as_text_and_nulls_are_empty() {
        let batch = RecordBatch::try_from_iter([
            ("age", Arc::new(Int64Array::from(vec![Some(41), None])) as ArrayRef),
            ("score", Arc::new(Float64Array::from(vec![Some(1.5), Some(2.0)])) as ArrayRef),
            ("name", Arc::new(StringArray::from(vec![Some("Asha"), None])) as ArrayRef),
        ])
        .unwrap();
        let t = table_from_batch(&batch, "b0").unwrap();
        assert_eq!(t.headers, ["age", "score", "name"]);
        assert_eq!(t.rows[0], ["41", "1.5", "Asha"]);
        assert_eq!(t.rows[1], ["", "2.0", ""]);
        let back = batch_from_table(&t).unwrap();
        assert_eq!(back.num_rows(), 2);
        assert_eq!(table_from_batch(&back, "b0").unwrap(), t);
    }

    #[test]
    fn an_empty_batch_keeps_its_columns() {
        let t = Table::new(vec!["a".into(), "b".into()], vec![], "x");
        let b = batch_from_table(&t).unwrap();
        assert_eq!((b.num_rows(), b.num_columns()), (0, 2));
    }
}
