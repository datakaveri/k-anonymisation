# Multi-tabular input examples

Two verified end-to-end examples for testing the CSV/JSON/Excel multi-tabular
input feature. Each folder has one input file and one config — copy both into
place and run:

```bash
rm -f data/* config/*.json output/*
cp examples/multitabular/demo1_two_sheet_join/patients.xlsx data/
cp examples/multitabular/demo1_two_sheet_join/config.json config/config.json
docker compose up --build
cat output/status.json
```

Clear `output/` too (or set `"clean_output": true` in the config): it is not
wiped automatically, so results from a previous demo stay alongside the new
ones — after running demo2 and then demo1 you would see both
`generalized_schools.csv` and `generalized_test.csv`. Each run logs leftovers it
found under the `cleanup` phase. `chunks/` is emptied automatically.

## demo1_two_sheet_join

`patients.xlsx` — 2 sheets, 6 records:
- **Patients**: `patient_id, Age, Blood Group, PIN Code`
- **Visits**: `patient_id, diagnosis_code`

`config.json` joins them on `patient_id` (single `sheet_joins` step) and
k-anonymizes on `Age`/`PIN Code`/`Blood Group` (k=2), using
`categorical_hierarchies` to generalize Blood Group by ABO group.
`restore_sheets: true` is set, so the run also produces
`output/generalized_test.xlsx` with the original `Patients`/`Visits` sheets
restored (anonymized).

## demo2_three_sheet_star_schema

`schools.xlsx` — 3 sheets, 12 records:
- **School master**: `school_id, school_type, district`
- **School amenities**: `school_id, toilets`
- **School snapshot**: `school_id, enrolment`

`config.json` chains two `sheet_joins` steps against the same `left` sheet
(`School master`) to build a star-schema join, then k-anonymizes on
`school_type`/`enrolment` (k=5). `restore_sheets: true` is set, so the run
also produces `output/generalized_schools.xlsx` with all three original
sheets restored (anonymized).

Both were run against the pipeline binary and produced `status: "success"`
with the expected joined columns in the flat generalized CSV, and — since
both configs set `restore_sheets: true` — a correctly-restored multi-sheet
`.xlsx` matching the original workbook structure.
