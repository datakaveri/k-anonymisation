"""Builds the join corpus: multi-sheet workbooks with a config, test keys, and a recorded CLI output.

    python3 generate_joins.py        # writes ./cases/join_*/{data.xlsx,config.json,testkeys/}

Same rules as generate.py: everything is invented and seeded, and the expected outputs are the command
line's own (run_cli.py --record), never written here. Kept apart from generate.py so regenerating the
single-table cases cannot disturb them.
"""
import json
import os
import random

from generate import BASE, BLOOD, DIAG, FIRST, KEYS, LAST, PINS
from xlsx_min import write_xlsx

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.join(HERE, "cases")
HOSPITALS = ["City General", "Lakeside", "St Mary", "Northgate"]
DISTRICTS = {"City General": "Central", "Lakeside": "East", "St Mary": "West", "Northgate": "North"}


def workbook(n_patients=60, seed=11, orphan_visits=2):
    r = random.Random(seed)
    patients, visits, vid = [], [], 0
    for i in range(n_patients):
        f, l = r.choice(FIRST), r.choice(LAST)
        patients.append({"id": f"P{1000 + i}", "name": f"{f} {l}", "phone": f"9{r.randint(100000000, 999999999)}",
                         "age": str(r.randint(18, 79)), "pin": str(r.choice(PINS)), "gender": r.choice(["M", "F"]),
                         "blood": r.choice(BLOOD), "hospital": r.choice(HOSPITALS), "note": r.choice(["stable", "referred", ""])})
        if i < n_patients * 3 // 4:  # the last quarter has no visits: a left join must keep them
            for _ in range(r.randint(1, 3)):
                vid += 1
                visits.append({"id": f"P{1000 + i}", "visit_id": f"V{vid:04d}", "visit_date": f"2025-{r.randint(1, 12):02d}-{r.randint(1, 28):02d}",
                               "diagnosis": r.choice(DIAG), "note": r.choice(["follow-up, 2 weeks", "none", 'said "ok"'])})
    for k in range(orphan_visits):  # visits of nobody in the patient sheet: inner drops them, right/outer keep them
        vid += 1
        visits.append({"id": f"P9{k:03d}", "visit_id": f"V{vid:04d}", "visit_date": "2025-01-01", "diagnosis": "Malaria", "note": "orphan"})
    # An awkward patient: blank hospital, a hospital with no row in the lookup, padded text.
    patients[3]["hospital"] = ""
    patients[5]["hospital"] = "Unlisted Clinic"
    patients[7]["name"] = " Padded Name "
    hospitals = [{"hospital": h, "district": DISTRICTS[h], "beds": str(40 + 10 * i)} for i, h in enumerate(HOSPITALS)]
    return patients, visits, hospitals


def sheet(rows, cols):
    return [cols] + [[row[c] for c in cols] for row in rows]


P_COLS = ["id", "name", "phone", "age", "pin", "gender", "blood", "hospital", "note"]
V_COLS = ["id", "visit_id", "visit_date", "diagnosis", "note"]
H_COLS = ["hospital", "district", "beds"]

QI = {"quasi_identifiers": {"numerical": [{"column": "age"}, {"column": "pin"}], "categorical": [{"column": "gender"}, {"column": "blood"}]},
      "size": {"age": 2, "pin": 10}, "categorical_hierarchies": BASE["categorical_hierarchies"],
      "k_anonymize": {"k": 5}, "suppression_limit": 0.1}
DIRECT = {"output_path": "anonymized.csv", "suppress": ["name"], "hashing_with_salt": ["id"], "shared_hash_salts": True,
          "encrypt": [{"phone": {"format_preserving": True}}]}


def cfg(**over):
    sec = {**DIRECT}
    for k, v in over.items():
        if v is None:
            sec.pop(k, None)
        else:
            sec[k] = v
    return {"data_type": "tabular", "tabular": sec}


def case(name, sheets, config, keys=KEYS):
    d = os.path.join(CASES, name)
    os.makedirs(os.path.join(d, "testkeys"), exist_ok=True)
    write_xlsx(os.path.join(d, "data.xlsx"), sheets)
    with open(os.path.join(d, "config.json"), "w") as f:
        json.dump(config, f, indent=2)
        f.write("\n")
    for fn, body in keys.items():
        with open(os.path.join(d, "testkeys", fn), "w") as f:
            json.dump(body, f, indent=2)
            f.write("\n")


def main():
    pat, vis, hos = workbook()
    P, V, H = ("patients", sheet(pat, P_COLS)), ("visits", sheet(vis, V_COLS)), ("hospitals", sheet(hos, H_COLS))
    star = [{"left": "patients", "right": "visits", "on": ["id"], "how": "left"},
            {"left": "patients", "right": "hospitals", "on": "hospital", "how": "left"}]
    # k-anonymity over a star join, then split back per sheet.
    case("join_star_restore", [P, V, H], cfg(**QI, sheet_joins=star, restore_sheets=True,
                                              masking=[{"column": "diagnosis", "masking_char": "#", "characters_to_mask": [1, 2]}]))
    # Inner join, a colliding non-key column (note -> note_x / note_y), column techniques only.
    case("join_inner_collide", [P, V], cfg(sheet_joins=[{"left": "patients", "right": "visits", "on": ["id"], "how": "inner"}],
                                            restore_sheets=True, masking=[{"column": "note_y", "masking_char": "#", "characters_to_mask": [1, 2, 3]}]))
    # Outer join keeps unmatched rows of both sheets; no restore, so the joined table itself is the output.
    case("join_outer_flat", [P, V], cfg(sheet_joins=[{"left": "patients", "right": "visits", "on": ["id"], "how": "outer"}]))
    # Right join with k-anonymity on columns that come from both sides.
    case("join_right_qi", [P, V], cfg(**QI, sheet_joins=[{"left": "patients", "right": "visits", "on": ["id"], "how": "right"}],
                                      restore_sheets=True))
    # Cross join (tiny: the product is the size of the output).
    case("join_cross", [("patients", sheet(pat[:6], P_COLS)), H], cfg(sheet_joins=[{"left": "patients", "right": "hospitals", "on": ["hospital"], "how": "cross"}],
                                                                      restore_sheets=True))
    # No sheet_joins, same columns in both sheets: SKALD stacks them.
    north, south = pat[:30], pat[30:]
    case("join_concat", [("north", sheet(north, P_COLS)), ("south", sheet(south, P_COLS))], cfg(**QI))
    # No sheet_joins, different columns: SKALD joins on the shared column(s), left.
    pat2 = [{k: v for k, v in p.items() if k not in ("note", "hospital")} for p in pat]
    vis2 = [{k: v for k, v in x.items() if k != "note"} for x in vis]
    case("join_auto", [("patients", sheet(pat2, [c for c in P_COLS if c not in ("note", "hospital")])),
                       ("visits", sheet(vis2, [c for c in V_COLS if c != "note"]))], cfg(**QI))


if __name__ == "__main__":
    main()
