# Multi-tabular input examples

Two verified end-to-end examples for testing the CSV/JSON/Excel multi-tabular
input feature. Each folder has one input file and one config — copy both into
place and run:

```bash
rm -f data/* config/*.json
cp examples/multitabular/demo1_two_sheet_join/patients.xlsx data/
cp examples/multitabular/demo1_two_sheet_join/config.json config/config.json
docker compose up --build
cat output/status.json
```

## demo1_two_sheet_join

`patients.xlsx` — 2 sheets, 6 records:
- **Patients**: `patient_id, Age, Blood Group, PIN Code`
- **Visits**: `patient_id, diagnosis_code`

`config.json` joins them on `patient_id` (single `sheet_joins` step) and
k-anonymizes on `Age`/`PIN Code`/`Blood Group` (k=2), using
`categorical_hierarchies` to generalize Blood Group by ABO group.

## demo2_three_sheet_star_schema

`schools.xlsx` — 3 sheets, 12 records:
- **School master**: `school_id, school_type, district`
- **School amenities**: `school_id, toilets`
- **School snapshot**: `school_id, enrolment`

`config.json` chains two `sheet_joins` steps against the same `left` sheet
(`School master`) to build a star-schema join, then k-anonymizes on
`school_type`/`enrolment` (k=5).

Both were run against the pipeline binary and produced `status: "success"`
with the expected joined columns in the generalized output.
