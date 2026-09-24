# NHA FHIR bundle de-identification

De-identification for NHA claim bundles once they arrive as **FHIR R4
Bundles** instead of raw extraction JSON. One bundle is still one patient.

- Code: `SKALD/src/pipeline/fhir_bundle.rs` (rule engine shared with `nested_json.rs`)
- Config: `config/nha_fhir.json`
- Run: `skald_pipeline --config config/nha_fhir.json`
- Refresh from NHA's technique sheets: `scripts/build_nha_fhir_code_rules.py`

Like the nested-JSON flow, `fhir_bundle: true` *replaces* the tabular pipeline
rather than feeding it. There is no cohort inside a bundle, so there is no k.
The status payload reports `"k_anonymity_applied": false`.

## What is different from nested JSON

| Nested JSON | FHIR bundle |
|---|---|
| Open key space (57k+ field names) | Fixed schema: a few hundred element paths |
| Rules over extraction keys | Rules over FHIR paths (`Observation.valueQuantity.value`) **plus** code rules over `Observation.code.text` |
| No links between records | `id` / `fullUrl` / `reference` graph, which has to stay consistent |
| Suppressed array element → `null` | Removed. FHIR JSON allows no `null`, `{}` or `[]` |
| A value lives in one place | The same value appears in several places (`meta.source`, attachment URL, narrative `text.div`, filename) |

## Three layers of policy

**1. Path rules.** These use the same buckets and glob syntax as nested JSON
(`keep`, `suppress`, `hashing_with_salt`, `free_text`, `masking`, `size`),
written as `ResourceType.element…`. The census path format
(`Patient.name[].text`) can be pasted straight back as a rule. The narrowest
matching pattern wins, and ties go to the safer action. `default_action` is
`suppress`.

**2. Code rules.** The technique sheets are keyed by the old extraction field
names. In FHIR those names survive only as `Observation.code.text`
(`"gps latitude"`). `code_rules` matches the normalised code text, each
`coding[].display`, or an exact `system|code`:

| Bucket | Effect on the Observation |
|---|---|
| `suppress` | Dropped entirely, and removed from every reference to it (`DiagnosticReport.result[]`) |
| `hashing_with_salt` | Its `value[x]` is pseudonymised |
| `free_text` | Released as-is: the NER pipeline has already cleaned it upstream |
| `keep` | Nothing extra: the path rules decide |

The field names come from the sheets. Entries containing `*` or `|` are
hand-written safety nets for PII-shaped names the sheets leave unlisted:
DOB, relatives, village and panchayat, IP/IPD/MRD numbers, religion, caste,
income, GPS, and so on.

**3. Propagation sweep.** Before walking a bundle, values at identifying paths
(`propagation.from`: patient name, identifiers, telecom, address, claim id,
hospital name…) are collected as needles. Any leaf that would be released
verbatim is checked against them in three forms:

- the whole value with separators stripped (`BOCW/BR/…` inside `BOCW_BR_…`);
- digit runs of 6 or more (the case number alone inside a URL path);
- name words of 4 or more letters (`KAILA SHI DEVI` against `kailashi%20devi.pdf`).

A hit suppresses the leaf. The census records it as
`propagated:<source path>`, never with the value. Path rules cover the copies
we know about. The sweep is there for the copies nobody listed yet: a census
row showing `propagated:` means a path rule is missing.

## Hashing: one salt per column

Salted hashing works like tabular `hashing_with_salt`: each column gets a
random 32-byte salt, and a value's token is the SHA-256 of salt + value (64 hex
characters). A *column* is the rule that chose the hash
(`Claim.identifier[].value`, `**.meta.source`, `code:aadhaar_number`), plus
`<resource id>` for id pseudonyms.

- When `input_path` is a folder, every bundle in it shares the same column
  salts. The same value in the same column gets the same token in every file.
- Different columns use different salts, so their tokens cannot be joined.
- Salts are persisted in `<output_directory>/fhir_bundle_salts.json`, so a
  folder processed across several runs still gets one token per value. This
  file is key material: back it up, and never release it with the output.
- Changing how a hashing rule is written starts a new column, which gets a
  new salt and new tokens.

## Dates

FHIR dates are fixed-position ISO 8601, so they are masked with the tabular
masker's `characters_to_mask`. Positions 9–10 (day) and 12–13, 15–16, 18–19
(time) are masked, which keeps the year and month:
`2025-04-21T10:30:00+05:30` → `2025-04-**T**:**:**+05:30`. The masked value is
not a valid FHIR date. `qi_constraints` precision from the nested-JSON flow is
rejected here.

## Structural handling (not configurable)

- **Resource ids** become UUID-shaped pseudonyms under the `<resource id>`
  column salt. `fullUrl` and every `reference` are rewritten to match.
  Absolute-URL references are dropped.
- **Output filenames** are `<input stem>_anonymised.fhir.json`. NHA input
  names are case ids, so **the released filename carries the case id in
  clear**, and the hashed claim id inside the file can be matched to it. Treat
  the output folder as identifying, or rename the files before release.
- **data-absent-reason** extensions are always kept. Other extensions are
  suppressed unless a rule keeps them.
- A suppressed primitive takes its `_element` sibling with it. A `text` block
  without a `div` is removed. Empty objects and arrays are removed.

## Current policy summary

**Suppressed:** names (patient, practitioner, related person, hospital); date of birth;
telecom; street, city and postcode; attachment URLs; narrative `text.div`;
source-fact identifiers; reference `display`; marital status; location
position; device lot and serial numbers; every unlisted path.

**Hashed:** claim id, `meta.source`, patient, encounter and coverage identifiers.

**Masked:** every clinical and administrative date → day and time masked.

**Released as free text (NER upstream):** `note[].text`,
`DiagnosticReport.conclusion`, CarePlan descriptions.

**Kept:** codes and code text, values and units, reference ranges,
medications and dosage, specimen and device types, document type and
category, gender, district and state.

## Known limitations

- **The samples carry almost no quasi-identifiers.** Patient has only a name,
  and every date is data-absent. If production bundles add `birthDate`,
  Encounter periods or identifiers, the rules above handle them, but the first
  real run should be a `dry_run` and its census reviewed.
- **The sweep over-suppresses rather than under-suppresses.** A common
  surname appearing in an unrelated kept field will take that field with it.
  The census shows every such case.
- **Nested-JSON and FHIR pseudonyms differ** for the same case: the flows
  use different salt files and hash formats.
- **`free_text` trusts the upstream NER.** The sweep still checks those
  values against the bundle's own identifiers, but it cannot catch a name the
  bundle does not contain elsewhere.
- **Output key order** is alphabetical (serde_json default), so
  `resourceType` is not first. FHIR JSON allows any order.
