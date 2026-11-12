"""End-to-end matrix for SKALD: every input shape × single / two-pass, run in parallel.

    cargo build --release --manifest-path SKALD/Cargo.toml
    pip install openpyxl            # for the XLSX input
    python scripts/e2e_matrix.py [RUN_DIR]

Synthetic data only. Every flow gets its own root under RUN_DIR (default: a new
temporary directory); each output is checked for k, l, leaked identifiers, key
placement and log content. Prints PASS/FAIL per flow and writes
RUN_DIR/e2e_results.json. Exit status 1 if any check fails.
"""
import csv, json, os, random, shutil, stat, subprocess, sys, tempfile, time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get("SKALD_BIN", os.path.join(REPO, "SKALD", "target", "release", "skald_pipeline"))
HERE = sys.argv[1] if len(sys.argv) > 1 else tempfile.mkdtemp(prefix="skald-e2e-")
RUNS = os.path.join(HERE, "runs")

# ── Synthetic population ─────────────────────────────────────────────────────
random.seed(2026)
DIAG = ["Diabetes", "Hypertension", "Asthma", "Tuberculosis", "Anaemia", "Malaria"]
BLOOD = ["A+", "A-", "B+", "B-", "O+", "O-", "AB+", "AB-"]
PINS = [560001, 560002, 560010, 560034, 560066, 560095]
FIRST = ["Ravi", "Lakshmi", "Arjun", "Priya", "Suresh", "Meena", "Kiran", "Anita", "Rahul", "Divya"]
LAST = ["Kumar", "Sharma", "Reddy", "Iyer", "Nair", "Patel", "Singh", "Das"]

def person(i, **over):
    first, last = random.choice(FIRST), random.choice(LAST)
    p = {
        "PatientId": f"P{100000 + i}",
        "Name": f"{first} {last} {i}",
        "Aadhaar": f"{random.randint(2000, 9999)} {random.randint(1000, 9999)} {random.randint(1000, 9999)}",
        "Phone": f"+91-{random.randint(6000000000, 9999999999)}",
        "Email": f"{first.lower()}.{last.lower()}{i}@example.org",
        "PAN": "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(5)) + f"{random.randint(1000, 9999)}" + random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        "VehicleNo": f"KA-{random.randint(10, 99)}-{random.choice('ABCDEFGH')}{random.choice('ABCDEFGH')}-{random.randint(1000, 9999)}",
        "Age": random.randint(20, 79),
        "Gender": random.choice(["M", "F"]),
        "Pincode": random.choice(PINS),
        "BloodGroup": random.choice(BLOOD),
        "Diagnosis": random.choice(DIAG),
        "Note": random.choice(["Follow-up in 2 weeks", "Referred, see report", "Stable, discharged\nreview next month", "Allergic to penicillin, noted"]),
    }
    p.update(over)
    return p

PEOPLE = [person(i) for i in range(600)]
PEOPLE.append(person(600, Age=99, Gender="F", Pincode=560001, BloodGroup="AB-", Diagnosis="HIV"))   # outlier
for j in range(6):                                                                                  # homogeneous cluster
    PEOPLE.append(person(601 + j, Age=71, Gender="M", Pincode=560095, BloodGroup="O+", Diagnosis="Cancer"))
COLS = list(PEOPLE[0].keys())
QI = ["Age", "Pincode", "Gender", "BloodGroup"]
IDENTIFIERS = ["Name", "Aadhaar", "Phone", "Email", "PAN", "PatientId", "VehicleNo"]

# ── Configs ──────────────────────────────────────────────────────────────────
def tabular_section(**over):
    s = {
        "output_path": "anonymized.csv",
        "suppress": ["Name"],
        "hashing_with_salt": ["Aadhaar"],
        "masking": [
            {"column": "Phone", "characters_to_mask": [5, 6, 7, 8, 9, 10, 11], "apply_order": ["characters"]},
            {"column": "Email", "regex_patterns": [{"type": "before", "delimiter": "@"}], "apply_order": ["regex"]},
        ],
        "encrypt": ["Note", {"PAN": {"format_preserving": True}}],
        "charcloak": ["VehicleNo"],
        "tokenization": [{"column": "PatientId", "prefix": "PT-", "digits": 8}],
        "quasi_identifiers": {"numerical": [{"column": "Age"}, {"column": "Pincode"}],
                              "categorical": [{"column": "Gender"}, {"column": "BloodGroup"}]},
        "categorical_hierarchies": {
            "Gender": {"M": ["Person"], "F": ["Person"]},
            "BloodGroup": {b: [b.rstrip("+-"), "*"] for b in BLOOD},
        },
        "size": {"Age": 2, "Pincode": 10},
        "k_anonymize": {"k": 5},
        "suppression_limit": 0.05,
        "l_diversity": {"l": 2, "sensitive_attributes": ["Diagnosis"]},
    }
    s.update(over)
    return s

# ── Inputs ───────────────────────────────────────────────────────────────────
def write_csv(path, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)

def write_json(path, rows):
    json.dump(rows, open(path, "w"), ensure_ascii=False, indent=1)

def write_xlsx(path, rows):
    import openpyxl
    wb = openpyxl.Workbook()
    a = wb.active
    a.title = "patients"
    pcols = [c for c in COLS if c not in ("Diagnosis", "Note")]
    a.append(pcols)
    for r in rows:
        a.append([r[c] for c in pcols])
    v = wb.create_sheet("visits")
    v.append(["PatientId", "Diagnosis", "Note"])
    for r in rows:
        v.append([r["PatientId"], r["Diagnosis"], r["Note"]])
    wb.save(path)

def nested_docs():
    docs = []
    for p in PEOPLE[:40]:
        docs.append({
            "case_id": p["PatientId"],
            "status": random.choice(["Open", "Closed"]),
            "citizen": {"name": p["Name"], "phone": p["Phone"], "aadhaar": p["Aadhaar"], "email": p["Email"],
                        "age": f"{p['Age']}Y", "gender": p["Gender"]},
            "vehicle_no": p["VehicleNo"],
            "complaint": {"text": "Road damaged near house", "category": random.choice(["Roads", "Water", "Power"])},
            "location": {"lat": 12.9 + random.random() / 10, "long": 77.5 + random.random() / 10},
        })
    return docs

NESTED_SECTION = {
    "nested_json": True,
    "input_path": "data/nested",
    "output_path": "nested_out",
    "default_action": "suppress",
    "keep": ["status", "complaint.category", "citizen.gender"],
    "hashing_with_salt": ["case_id"],
    "masking": [{"column": "citizen.age", "characters_to_mask": [2], "apply_order": ["characters"]}],
    "charcloak": ["vehicle_no"],
    "tokenization": [{"column": "citizen.phone", "prefix": "PH-", "digits": 8}],
    "encrypt": ["citizen.email", {"citizen.aadhaar": {"format_preserving": True}}],
}

def fhir_bundle(p, n):
    pat = f"pat-{n}"
    return {"resourceType": "Bundle", "type": "collection", "entry": [
        {"fullUrl": f"urn:uuid:{pat}", "resource": {"resourceType": "Patient", "id": pat, "name": [{"text": p["Name"]}],
                                                    "gender": "male" if p["Gender"] == "M" else "female", "birthDate": "1970-01-01",
                                                    "telecom": [{"system": "phone", "value": p["Phone"]}]}},
        {"fullUrl": f"urn:uuid:obs-{n}", "resource": {"resourceType": "Observation", "id": f"obs-{n}", "status": "final",
                                                      "code": {"text": "hemoglobin", "coding": [{"system": "http://loinc.org", "code": "718-7", "display": "Hemoglobin"}]},
                                                      "subject": {"reference": f"urn:uuid:{pat}"},
                                                      "valueQuantity": {"value": round(9 + random.random() * 5, 1), "unit": "g/dL"}}},
        {"fullUrl": f"urn:uuid:org-{n}", "resource": {"resourceType": "Organization", "id": f"org-{n}", "name": "EXAMPLE CARE HOSPITAL"}},
    ]}

def fhir_section():
    # A small generic policy: keep clinical values and codes, pseudonymise
    # ids, suppress everything else (default-deny).
    return {
        "fhir_bundle": True,
        "input_path": "data/fhir",
        "output_path": "fhir_out",
        "default_action": "suppress",
        "keep": ["Bundle.type", "**.status", "**.resourceType", "Patient.gender",
                 "**.code.text", "**.coding[].system", "**.coding[].code", "**.coding[].display",
                 "Observation.valueQuantity.*"],
        "suppress": ["Patient.name.**", "Patient.telecom.**", "Patient.birthDate", "Organization.name"],
        "propagation": {"enabled": True, "min_length": 6, "from": ["Patient.name.**", "Patient.telecom.**"]},
    }

# ── Running ──────────────────────────────────────────────────────────────────
def new_root(name):
    root = os.path.join(RUNS, name)
    shutil.rmtree(root, ignore_errors=True)
    for d in ("config", "data", "output"):
        os.makedirs(os.path.join(root, d))
    return root

def run(root, section, label):
    cfg = os.path.join(root, "config", f"{label}.json")
    json.dump({"data_type": "t", "t": section}, open(cfg, "w"), indent=1)
    t0 = time.time()
    p = subprocess.run([BIN, "--root", root, "--config", cfg], capture_output=True, text=True)
    st = json.load(open(os.path.join(root, "output", "status.json")))
    shutil.copy(os.path.join(root, "output", "status.json"), os.path.join(root, f"status_{label}.json"))
    shutil.copy(os.path.join(root, "output", "pipeline.log"), os.path.join(root, f"pipeline_{label}.log"))
    return {"label": label, "rc": p.returncode, "secs": round(time.time() - t0, 2), "status": st}

def read_output_csv(root, name="anonymized.csv"):
    path = os.path.join(root, "output", name)
    with open(path, newline="") as f:
        return list(csv.DictReader(f))

def check_tabular(root, label, res, k=5, l=2, expect_rows=len(PEOPLE)):
    checks = {}
    st = res["status"]
    checks["status success"] = st.get("status") == "success"
    if not checks["status success"]:
        return checks
    out = read_output_csv(root)
    o = st["outputs"]
    removed = o.get("removed_records", 0)
    checks["rows published + removed = input"] = len(out) + removed == expect_rows
    classes = defaultdict(list)
    for r in out:
        classes[tuple(r[c] for c in QI)].append(r)
    checks[f"every class (incl. '*') has >= k={k}"] = all(len(v) >= k for v in classes.values())
    checks[f"every class has >= l={l} distinct Diagnosis"] = all(len({r["Diagnosis"] for r in v}) >= l for v in classes.values())
    blob = open(os.path.join(root, "output", "anonymized.csv")).read()
    leaked = [c for c in IDENTIFIERS for p in PEOPLE if c != "VehicleNo" and str(p[c]) in blob]
    checks["no raw identifier in output"] = not leaked
    checks["Name column removed"] = "Name" not in out[0]
    hiv_classes = [v for v in classes.values() if any(r["Diagnosis"] == "HIV" for r in v)]
    checks["HIV outlier hidden (its class >= k and >= l diagnoses, or removed)"] = all(
        len(v) >= k and len({r["Diagnosis"] for r in v}) >= l for v in hiv_classes)
    checks["no class discloses a single diagnosis (Cancer cluster)"] = all(
        len({r["Diagnosis"] for r in v}) > 1 for v in classes.values())
    logtxt = open(os.path.join(root, f"pipeline_{label}.log")).read()
    checks["no raw identifier in log"] = not any(str(p[c]) in logtxt for p in PEOPLE[:50] for c in ("Name", "Aadhaar", "Phone", "Email", "PAN"))
    checks["log has run summary"] = "Run summary" in logtxt and "DM* (sum of squared class sizes)" in logtxt
    checks["log has per-technique counts"] = "values transformed per technique" in logtxt
    keys = os.path.join(root, "keys")
    keyfiles = sorted(os.listdir(keys)) if os.path.isdir(keys) else []
    checks["key files only in keys/ (0600)"] = bool(keyfiles) and all(
        stat.S_IMODE(os.stat(os.path.join(keys, f)).st_mode) == 0o600 for f in keyfiles) and not any(
        f in os.listdir(os.path.join(root, "output")) for f in ("symmetric_keys.json", "token_vault.json", "fpe_encrypt_keys.json"))
    checks["scratch chunks/ empty after run"] = not os.listdir(os.path.join(root, "chunks"))
    # technique spot-checks
    r0 = out[0]
    checks["PAN: FPE keeps shape AAAAA9999A"] = all(len(r["PAN"]) == 10 and r["PAN"][:5].isalpha() and r["PAN"][5:9].isdigit() for r in out)
    checks["Note: AES-SIV ENC1$"] = all(r["Note"].startswith("ENC1$") for r in out)
    checks["PatientId: PT- tokens"] = all(r["PatientId"].startswith("PT-") and len(r["PatientId"]) == 11 for r in out)
    checks["Email local part masked"] = all(r["Email"].split("@")[0].strip("*") == "" for r in out)
    checks["Aadhaar hashed (64 hex)"] = all(len(r["Aadhaar"]) == 64 for r in out)
    return checks

def flow_single(fmt):
    root = new_root(f"single_{fmt}")
    write_input(root, fmt)
    sec = tabular_section(**xlsx_extras(fmt))
    res = run(root, sec, "single")
    res["checks"] = check_tabular(root, "single", res)
    res["extra_outputs"] = sorted(os.listdir(os.path.join(root, "output")))
    return {"flow": f"single pass {fmt}", "root": root, "steps": [res]}

def flow_two(fmt, chosen):
    root = new_root(f"two_{'grid' if chosen else 'ownk'}_{fmt}")
    write_input(root, fmt)
    p1 = tabular_section(**xlsx_extras(fmt))
    p1["pass"] = "pass1"
    p1.pop("k_anonymize")
    r1 = run(root, p1, "pass1")
    r1["checks"] = {
        "pass1 success": r1["status"].get("status") == "success",
        "awaiting_pass2": r1["status"].get("phase") == "awaiting_pass2",
        "grid has 12 cells": len(r1["status"]["outputs"].get("parameter_grid", [])) == 12,
        "pass1 writes no data file": not os.path.exists(os.path.join(root, "output", "anonymized.csv")),
        "log has grid table": "best_node" in open(os.path.join(root, "pipeline_pass1.log")).read(),
    }
    grid = r1["status"]["outputs"]["parameter_grid"]
    cell = next(c for c in grid if c["feasible"] and c["k"] == 5 and c["suppression_limit"] == 0.1)
    p2 = tabular_section(**xlsx_extras(fmt))
    p2["pass"] = "pass2"
    p2["k_anonymize"] = {"k": cell["k"]}
    p2["suppression_limit"] = cell["suppression_limit"]
    if chosen:
        p2["generalization_node"] = cell["generalization_node"]
    r2 = run(root, p2, "pass2")
    r2["checks"] = check_tabular(root, "pass2", r2, k=cell["k"])
    flow_kind = r2["status"].get("outputs", {}).get("flow")
    r2["checks"]["flow is " + ("CHOSEN_NODE" if chosen else "OLA-2")] = (flow_kind == "CHOSEN_NODE") == chosen
    if chosen:
        a = r2["status"]["outputs"]["anonymisation_summary"]
        r2["checks"]["pass2 DM* == grid cell DM*"] = a["dm_star"] == cell["dm_star"]
        r2["checks"]["pass2 suppressed == grid cell"] = a["suppressed_records"] == cell["suppression_count"]
    r2["grid_cell"] = cell
    r2["extra_outputs"] = sorted(os.listdir(os.path.join(root, "output")))
    return {"flow": f"two pass {fmt} ({'grid cell → generalization_node' if chosen else 'own k → OLA-2'})", "root": root, "steps": [r1, r2]}

def flow_preprocess_only():
    root = new_root("preprocess_only_csv")
    write_input(root, "csv")
    sec = tabular_section()
    for key in ("quasi_identifiers", "categorical_hierarchies", "size", "k_anonymize", "l_diversity", "suppression_limit"):
        sec.pop(key)
    res = run(root, sec, "single")
    out = read_output_csv(root)
    blob = open(os.path.join(root, "output", "anonymized.csv")).read()
    res["checks"] = {
        "status success": res["status"].get("status") == "success",
        "pass is preprocess_only": res["status"]["outputs"].get("pass") == "preprocess_only",
        "all rows kept": len(out) == len(PEOPLE),
        "no raw identifier in output": not any(str(p[c]) in blob for p in PEOPLE for c in ("Name", "Aadhaar", "Phone", "Email", "PAN", "PatientId")),
        "QIs released as-is (no k configured)": out[0]["Age"].isdigit(),
    }
    return {"flow": "preprocess-only csv (no QIs)", "root": root, "steps": [res]}

def flow_nested(two_pass):
    root = new_root(f"nested_{'twopass' if two_pass else 'single'}")
    os.makedirs(os.path.join(root, "data", "nested"))
    docs = nested_docs()
    for i, d in enumerate(docs):
        json.dump(d, open(os.path.join(root, "data", "nested", f"complaint_{i:03}.json"), "w"))
    sec = dict(NESTED_SECTION)
    if two_pass:
        sec["pass"] = "pass1"
    res = run(root, sec, "single")
    outdir = os.path.join(root, "output", "nested_out")
    files = sorted(f for f in os.listdir(outdir) if f.endswith(".json")) if os.path.isdir(outdir) else []
    blob = "".join(open(os.path.join(outdir, f)).read() for f in files)
    raw = [p for p in PEOPLE[:40] for c in ("Name", "Aadhaar", "Phone", "Email", "PatientId", "VehicleNo") if str(p[c]) in blob]
    sample = json.load(open(os.path.join(outdir, files[0]))) if files else None
    res["checks"] = {
        "status ok": res["status"].get("status") in ("ok", "success"),
        "one output per input": len(files) == len(docs),
        "no raw identifier in documents": not raw,
        "default suppress removed location": "lat" not in blob,
        "census written": os.path.exists(os.path.join(outdir, "nested_json_census.csv")),
        "key files only in keys/ (0600)": all(stat.S_IMODE(os.stat(os.path.join(root, "keys", f)).st_mode) == 0o600 for f in os.listdir(os.path.join(root, "keys"))),
    }
    res["sample_document"] = sample
    return {"flow": "nested JSON" + (" with pass: pass1 (two-pass not applicable)" if two_pass else ""), "root": root, "steps": [res]}

def flow_fhir(two_pass):
    root = new_root(f"fhir_{'twopass' if two_pass else 'single'}")
    os.makedirs(os.path.join(root, "data", "fhir"))
    for i, p in enumerate(PEOPLE[:20]):
        json.dump(fhir_bundle(p, i), open(os.path.join(root, "data", "fhir", f"CASE_TEST_{i:04}.fhir.json"), "w"))
    sec = fhir_section()
    if two_pass:
        sec["pass"] = "pass1"
    res = run(root, sec, "single")
    outdir = os.path.join(root, "output", "fhir_out")
    files = sorted(f for f in os.listdir(outdir) if f.endswith(".fhir.json")) if os.path.isdir(outdir) else []
    blob = "".join(open(os.path.join(outdir, f)).read() for f in files)
    res["checks"] = {
        "status ok": res["status"].get("status") in ("ok", "success"),
        "one output per bundle": len(files) == 20,
        "no patient names or phones": not any(p["Name"] in blob or p["Phone"] in blob for p in PEOPLE[:20]),
        "observation values kept": "valueQuantity" in blob,
        "salts only in keys/ (0600)": all(stat.S_IMODE(os.stat(os.path.join(root, "keys", f)).st_mode) == 0o600 for f in os.listdir(os.path.join(root, "keys"))),
    }
    res["sample_document"] = json.load(open(os.path.join(outdir, files[0]))) if files else None
    return {"flow": "FHIR bundles" + (" with pass: pass1 (two-pass not applicable)" if two_pass else ""), "root": root, "steps": [res]}

def write_input(root, fmt):
    d = os.path.join(root, "data")
    {"csv": lambda: write_csv(os.path.join(d, "people.csv"), PEOPLE),
     "json": lambda: write_json(os.path.join(d, "people.json"), PEOPLE),
     "xlsx": lambda: write_xlsx(os.path.join(d, "people.xlsx"), PEOPLE)}[fmt]()

def xlsx_extras(fmt):
    if fmt != "xlsx":
        return {}
    return {"sheet_joins": [{"left": "patients", "right": "visits", "on": "PatientId", "how": "left"}], "restore_sheets": True}

if __name__ == "__main__":
    os.makedirs(RUNS, exist_ok=True)
    jobs = [lambda f=f: flow_single(f) for f in ("csv", "json", "xlsx")]
    jobs += [lambda f=f, c=c: flow_two(f, c) for f in ("csv", "json", "xlsx") for c in (True, False)]
    jobs += [flow_preprocess_only, lambda: flow_nested(False), lambda: flow_nested(True), lambda: flow_fhir(False), lambda: flow_fhir(True)]
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=len(jobs)) as ex:
        results = list(ex.map(lambda j: j(), jobs))
    json.dump({"wall_seconds": round(time.time() - t0, 1), "results": results}, open(os.path.join(HERE, "e2e_results.json"), "w"), indent=1, default=str)
    for r in results:
        bad = [f"{s['label']}: {k}" for s in r["steps"] for k, v in s.get("checks", {}).items() if not v]
        print(f"{'PASS' if not bad else 'FAIL'}  {r['flow']}" + ("" if not bad else f"  -> {bad}"))
    print("wall", round(time.time() - t0, 1), "s — results in", HERE)
    failed = any(not v for r in results for s in r["steps"] for v in s.get("checks", {}).values())
    sys.exit(1 if failed else 0)
