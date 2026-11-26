"""Builds the per-document corpus: synthetic FHIR bundles and nested JSON documents with configs.

    python3 generate_documents.py        # writes ./documents/{fhir,nested}/{config*.json,docs/*.json}

Everything is invented: names come from short lists, ids from a counter, and
the shapes follow the NHA claim bundles without any real value. The expected
outputs are not written here; tests run the SKALD command line over these files
and compare, so the reference is what SKALD itself produces.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "documents")
DAR = "http://hl7.org/fhir/StructureDefinition/data-absent-reason"

PEOPLE = [
    ("ARJUN TESTNAME VERMA", "male", "1970-01-01", "9000000011"),
    ("MEERA SAMPLE IYER", "female", "1985-06-15", "9000000022"),
    ("KIRAN EXAMPLE DAS", "female", "2001-12-31", "9000000033"),
]


def uid(n):
    return f"11111111-0000-5000-8000-{n:012d}"


def entry(res):
    return {"fullUrl": f"urn:uuid:{res['id']}", "resource": res}


def fhir_bundle(i):
    name, gender, dob, phone = PEOPLE[i]
    case = f"TESTCASE_ST_2025_R0_100000{i:04d}"
    base = i * 100
    pat, hb, gps, dr, nurse, uhid, org, doc = (uid(base + k) for k in range(1, 9))
    meta = {"source": f"urn:example:{case}", "tag": [{"system": "urn:example:origin", "code": "structure"}]}
    pref = {"reference": f"urn:uuid:{pat}"}
    entries = [
        entry({"resourceType": "Patient", "id": pat, "meta": meta, "name": [{"text": name}], "gender": gender,
               "birthDate": dob, "telecom": [{"system": "phone", "value": phone}],
               "identifier": [{"system": "urn:example:id", "value": f"urn:example:PID-{i}-77{i}"}]}),
        entry({"resourceType": "Claim", "id": f"claim{i}", "meta": meta, "status": "active",
               "identifier": [{"value": case.replace("_", "/")}], "patient": pref,
               "_status": {"extension": [{"url": DAR, "valueCode": "unknown"}]}}),
        entry({"resourceType": "Observation", "id": hb, "meta": meta, "status": "final",
               "code": {"text": "hemoglobin", "coding": [{"system": "http://loinc.org", "code": "718-7", "display": "Hemoglobin"}]},
               "subject": pref, "valueQuantity": {"value": 9.1 + i, "unit": "g/dL"},
               "text": {"status": "generated", "div": f"<div>Observation hemoglobin; {name.split()[0]}</div>"}}),
        entry({"resourceType": "Observation", "id": gps, "meta": meta, "status": "final",
               "code": {"text": "gps latitude", "coding": [{"system": "http://loinc.org", "code": "42130-5", "display": "Latitude"}]},
               "subject": pref, "valueQuantity": {"value": 12.345678 + i, "unit": "deg"}}),
        entry({"resourceType": "Observation", "id": nurse, "meta": meta, "status": "final",
               "code": {"text": "nurse remarks"}, "subject": pref,
               "valueString": f"{name.split()[0]} was calm, family present"}),
        entry({"resourceType": "Observation", "id": uhid, "meta": meta, "status": "final",
               "code": {"text": "patient uhid"}, "subject": pref, "valueString": f"UHID-{i}-55{i}"}),
        entry({"resourceType": "DiagnosticReport", "id": dr, "status": "final",
               "code": {"text": "investigation report"}, "subject": pref,
               "conclusion": f"Mild anaemia noted for {name.split()[0]}.",
               "result": [{"reference": f"urn:uuid:{hb}"}, {"reference": f"urn:uuid:{gps}"}]}),
        entry({"resourceType": "Organization", "id": org, "name": "EXAMPLE CARE HOSPITAL, TESTPUR", "alias": ["E C HOSPITAL"]}),
        entry({"resourceType": "DocumentReference", "id": doc, "status": "current", "subject": pref,
               "type": {"text": "clinical notes"},
               "category": [{"text": "Photo of " + name.split()[0] + " at bedside"}],
               "content": [{"attachment": {"url": "store/1111/forms/1/attachment/" + name.lower().replace(" ", "%20") + ".pdf",
                                           "title": "page 1"}}]}),
    ]
    return {"resourceType": "Bundle", "type": "collection", "entry": entries}


FHIR_CONFIG = {
    "data_type": "fhir",
    "fhir": {
        "fhir_bundle": True, "dry_run": False, "input_path": "data/fhir", "output_path": "fhir",
        "output_directory": "output", "default_action": "suppress",
        "keep": ["Bundle.type", "**.status", "**.meta.tag[].system", "**.meta.tag[].code", "**.coding[].system",
                 "**.coding[].code", "**.coding[].display", "**.code.text", "**.type.text", "**.category[].text",
                 "Observation.valueQuantity.*", "Patient.gender", "DocumentReference.content[].attachment.title"],
        "suppress": ["Patient.name.**", "Organization.name", "Organization.alias", "**.attachment.url", "**.text.div",
                     "**.identifier[].system", "Patient.identifier[].value"],
        "hashing_with_salt": ["Claim.identifier[].value", "**.meta.source"],
        "free_text": ["DiagnosticReport.conclusion"],
        "masking": [{"column": "Patient.birthDate", "masking_char": "*", "apply_order": ["characters"],
                     "characters_to_mask": [6, 7, 8, 9, 10]},
                    {"column": "Patient.telecom[].value", "masking_char": "*", "apply_order": ["regex"],
                     "regex_patterns": [{"regex": "^(.*?)(.{0,4})$", "mask_groups": {"1": "full"}}]}],
        "drop_resources": ["Organization"],
        "code_rules": {"suppress": ["gps_*"], "free_text": ["nurse_remarks"], "hashing_with_salt": ["*uhid*"],
                       "keep": ["hemoglobin"]},
        "propagation": {"enabled": True, "min_length": 6, "from": ["Patient.name.**", "Patient.telecom[].value"]},
        "hash_strip_prefixes": ["urn:example:"],
    },
}

NESTED_CONFIG = {
    "data_type": "nested",
    "nested": {
        "nested_json": True, "dry_run": False, "input_path": "data/nested", "output_path": "nested",
        "output_directory": "output", "default_action": "suppress",
        "keep": ["total_pages", "pages[].page_number", "pages[].total_pages", "pages[].document",
                 "**.hospital_state", "**.diagnosis"],
        "suppress": ["**.patient_name", "**.address", "**.gps_*"],
        "hashing_with_salt": ["case_id", "**.mobile_number"],
        "free_text": ["**.nurse_remarks"],
        "masking": [{"column": "**.pincode", "masking_char": "*", "apply_order": ["characters"],
                     "characters_to_mask": [4, 5, 6]}],
        "encrypt": ["**.aadhaar_number", {"**.ration_card": {"format_preserving": True}}],
        "filename": ["pages[].link"],
    },
}


def nested_doc(i):
    name, _, _, phone = PEOPLE[i]
    pages = []
    for p in range(1, 4):
        pages.append({
            "document": f"discharge_{p}", "link": f"https://store.example.org/media/case/{i}/page_{p}.jpg?Signature=abc{p}",
            "page_number": p, "total_pages": 3,
            "extracted_data": {
                "patient_name": name, "mobile_number": phone, "address": f"{p} Test Street, Testpur",
                "pincode": f"56000{p}", "hospital_state": "KARNATAKA", "diagnosis": "anaemia",
                "aadhaar_number": f"4000 0000 00{i}{p}", "ration_card": f"RC{i}00{p}XYZ",
                "gps_latitude": 12.5 + p, "nurse_remarks": f"{name.split()[0]} is stable",
                "unlisted_field": "dropped by default",
            },
        })
    return {"case_id": f"TESTCASE/ST/2025/R0/100000{i:04d}", "total_documents": 1, "total_pages": 3, "pages": pages}


def write(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")


def main():
    write(os.path.join(OUT, "fhir", "config.json"), FHIR_CONFIG)
    pseud = json.loads(json.dumps(FHIR_CONFIG))
    pseud["fhir"]["output_names"] = "pseudonym"
    write(os.path.join(OUT, "fhir", "config_pseudonym.json"), pseud)
    write(os.path.join(OUT, "nested", "config.json"), NESTED_CONFIG)
    for i in range(3):
        write(os.path.join(OUT, "fhir", "docs", f"TESTCASE_ST_2025_R0_100000{i:04d}.fhir.json"), fhir_bundle(i))
        write(os.path.join(OUT, "nested", "docs", f"case_{i}.json"), nested_doc(i))


if __name__ == "__main__":
    main()
