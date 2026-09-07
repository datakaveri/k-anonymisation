# NHA nested-JSON de-identification

De-identification for NHA claim bundles (BOCW, AROGYAK) — nested JSON where
**one file is one patient**.

- Code: `SKALD/src/pipeline/nested_json.rs`
- Config: `config/nha_nested.json`
- Run: `skald_pipeline --config config/nha_nested.json`

## Why this is not the k-anonymity flow

k-anonymity protects a record by hiding it among at least k others that share
its quasi-identifiers. These inputs are one document per patient: there is no
cohort, so no equivalence classes, no k, and no generalization lattice to
search. Feeding them to the tabular flow would flatten a single subject into a
single row and then "anonymize" a cohort of one.

What protects one of these documents is removing the identifiers it contains
and coarsening the quasi-identifiers that remain. So this is a
structure-preserving redaction pass: nested JSON in, the same nested JSON out,
one output file per input file.

`nested_json.enabled` therefore *replaces* the tabular pipeline rather than
feeding it — `run_pipeline_with` returns as soon as it sees the flag, and the
status payload reports `"k_anonymity_applied": false`.

## The input shape

```json
{
  "case_id": "BOCW/UP/2025/R2/1007213122",
  "total_documents": 2,
  "total_pages": 13,
  "pages": [
    {
      "document": "Any other document",
      "link": "…/attachment/CLAIM DOCUMENTS.pdf",
      "page_number": 1,
      "total_pages": 12,
      "extracted_data": { "document_type": "clinical_notes", "…": "…" }
    }
  ]
}
```

Corpus profile from the 50-file sample (`BOCW` × BR/UP/MP, `AROGYAK` × KL):
~50 KB median, 255 KB largest, 1–97 pages per bundle, 11 `document_type`
values (`investigation_report`, `clinical_notes`, `identity_document`,
`discharge_summary`, `billing`, `consent_form`, …).

## Why default-deny

`extracted_data` has **no fixed schema** — it is whatever the extraction model
read off that page. A census of only the first 5 KB of 50 sample files already
turns up **2365 distinct keys**, and the tail grows with every new document:
`handwritten_notes_3`, `malayalam_text_2`,
`lab_serum_bilirubin_direct_method`, `bed_sheet_color`, `visitor_clothing`.

An open-ended key space cannot be secured by listing the keys to remove,
because the next document always brings a key nobody listed. So:

- `default_action` is `suppress`; rules say what to **keep**.
- Rules are glob patterns over JSON **paths**, not literal key names.
- The config is rejected outright if `default_action` is `suppress` and no
  rules are given, rather than silently emitting empty documents.

## What changed from the previous JSON flow

`multitabular::read_json_sheet` handles a flat array-of-objects and could not
be stretched to cover this:

| Previous behaviour | Why it breaks on NHA data |
|---|---|
| Requires a top-level **array** | Each file is a single top-level **object** → `DATA_JSON_INVALID` |
| `json_scalar_to_string` stringifies non-scalars | `pages` / `extracted_data` subtrees land raw in one cell, PII intact |
| Columns = union of top-level keys | ~2365+ sparse keys, and no per-key policy |
| `suppress` matches column names exactly and **hard-errors** on a missing column | Cannot express "suppress everything unlisted"; any fixed list errors on the first document lacking a key |
| No glob or path matching anywhere | Cannot write `**.extracted_data.*name*` |

Nothing in the old flow was changed — `nested_json` is an additional terminal
flow beside it.

## Actions

| Action | Effect |
|---|---|
| `keep` | Value passes through unchanged |
| `suppress` | Key removed from its parent object entirely |
| `redact` | Key kept, non-empty value replaced with `redaction_placeholder` |
| `hash` | Stable salted SHA-256 token (16 hex chars) — pseudonym, keeps linkage |
| `age_band:N` | `"49Y"` → `"45-49"`; `90+` collapses to one band |
| `date_month` / `date_year` | `"21-Apr-2025 03:11 PM"` → `"2025-04"` / `"2025"` |
| `truncate:N` | Keep the leading N characters |

Messy real values are handled: ages arrive as `49Y`, `18 Years`,
`24 Yrs./Male`, `2 वर्ष`; dates as `27/10/2024`, `21/4/25`,
`2025-04-21 2:24 pm`, `Oct 29, 2024, 04:57 p.m.`. A value that will not parse
is **redacted, never passed through** (`redact_unparseable`, default true).

Structure is always preserved: containers are walked rather than matched, so no
pattern can suppress a whole subtree; an object whose every leaf is suppressed
stays as an empty object; a suppressed array element becomes `null` rather than
shifting every later index and making page numbers lie.

## Pattern syntax

- `.` separates segments; array indices are normalised to `[]`, so
  `pages.[].extracted_data.patient_name` covers every page.
- `**` spans any number of segments — `**.patient_name` matches it at any depth.
- `*` inside a segment matches any run of characters within that segment.
- Matching is case-insensitive.
- **First match wins**, so narrow exceptions must sit above the broad patterns
  they carve out of.

## Rule order is load-bearing

The first draft of `config/nha_nested.json` had three defects that the census
caught and that no error would have:

- `**.*_id` sat above `case_id`, so the case was **suppressed instead of
  hashed** — every bundle lost its linkage.
- `**.*_number` sat above `pages.[].page_number`, silently destroying page
  ordering.
- `**.*age*` matched `total_pages` — "total_p**age**s" — and banded the page
  count into `"0-4"`.

All three produce a successful run and plausible-looking output. Structural
exact paths now sit at the top of the rules array, the age pattern is narrow
(`**.patient_age`, `**.age`), and
`shipped_nha_config_keeps_document_structure_intact` asserts the resolved
action for each of them.

## The key census is the release gate

Every run writes `output/nha/nested_json_census.csv`:

```
path,documents_seen,non_empty,action,matched_by,example_value
pages[].extracted_data.patient_name,113,113,suppress,**.*name*,
pages[].extracted_data.document_type,176,176,keep,**.document_type,discharge_summary
pages[].extracted_data.visitor_clothing,1,1,suppress,<default>,
```

`matched_by` names the rule that decided, or `<default>`. Example values are
sampled **only from kept paths** — an example drawn from a suppressed path
would put the exact PII under discussion into a report that then gets passed
around to tune the rules.

With 2000+ keys this report, not the config file, is the thing to review before
a release: everything marked `keep` is in the released documents. Rows marked
`<default>` are keys no rule anticipated — read them to find the identifying
field no pattern has caught yet.

## Current policy summary

**Suppressed** — names (patient, guardian, doctor, hospital, ward, lab);
Aadhaar / ABHA / PM-JAY / UHID / IP / IPD / CR / registration / receipt /
invoice / barcode / serial numbers; phone, mobile, email, website; addresses;
`latitude` / `longitude` / `map_provider` (photo pages carry EXIF geolocation
that pins a patient to a building); ward, bed, room, floor; `link` (the
attachment path embeds provider ids *and* the patient's name — `DISCHARGE
SURESH MEENA.pdf`); photo-scene descriptors (clothing, posture, bed
furnishings); income, religion, caste; date of birth and year of birth; all
free text.

**Redacted** — signatures and stamps, keeping the fact without the identity.

**Hashed** — `case_id`.

**Coarsened** — `patient_age` → 5-year bands; all dates and timestamps →
year-month.

**Kept** — diagnoses, procedures, lab values, vitals, examinations,
treatments, medications, `document_type`, gender, `district`/`state`,
occupation, and the bundle's own structure.

## Known limitations

- **Free text is dropped, not anonymized.** Clinical narrative, handwritten
  notes and the Malayalam/Hindi consent affidavits carry names, villages and
  relatives inline, so no pattern over *keys* can make them safe. Route them
  through `free_text_anonymization` (NER) as a separate pass if the narrative
  is needed — do not simply flip those rules to `keep`.
- **Combined `age_sex` fields are suppressed**, not split: `age_band` would
  read the age out of `"24 Yrs./Male"` and silently drop the sex half. Use
  `patient_age` and `patient_gender`. Splitting them in the extractor would
  recover the field.
- **`hash_salt` is key material.** The shipped config carries
  `REPLACE_ME_AT_DEPLOY_TIME`; with the salt, any guessed `case_id` can be
  re-derived. Inject it at deploy time. With no salt configured the run
  generates one and warns that pseudonyms will not be reproducible.
- **A rare diagnosis can itself identify**, even with every identifier gone.
  Kept clinical fields are sensitive attributes, not identifiers — bounding
  that risk is the release agreement's job, not this pass's.
- **Malformed documents are skipped, not fatal** (reported in the log and in
  `documents_skipped`). A corpus of extraction outputs reliably contains a few
  duds, and failing the whole run over one would mean no output at all.
