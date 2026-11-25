"""Builds the conformance corpus: synthetic CSVs, configs and fixed test keys.

    python3 generate.py            # writes ./cases/<case>/{data.csv,config.json,testkeys/}

Everything here is invented (names are drawn from short lists, numbers from a
seeded RNG) and the "keys" are fixed test values, not secrets. The expected
outputs are NOT written by this script: they are the command line's own output,
captured by `run_cli.py --record` from a known-good build, so a later build is
checked against what SKALD actually produced, not against a second opinion.
"""
import csv, json, os, random

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.join(HERE, "cases")

FIRST = ["Asha", "Ravi", "Meena", "Kiran", "Divya", "Arjun", "Priya", "Suresh", "Anita", "Rahul"]
LAST = ["Kumar", "Sharma", "Reddy", "Iyer", "Nair", "Patel", "Singh", "Das"]
BLOOD = ["A+", "A-", "B+", "B-", "O+", "O-", "AB+", "AB-"]
DIAG = ["Diabetes", "Hypertension", "Asthma", "Anaemia", "Malaria", "Cancer"]
PINS = [560001, 560002, 560010, 560034, 560066, 560095, 560100]
COLS = ["id", "name", "phone", "email", "age", "pin", "gender", "blood", "diagnosis", "note"]


def rows(n, seed):
    r = random.Random(seed)
    out = []
    for i in range(n):
        f, l = r.choice(FIRST), r.choice(LAST)
        out.append({
            "id": f"P{1000 + i}", "name": f"{f} {l}",
            "phone": f"9{r.randint(100000000, 999999999)}",
            "email": f"{f.lower()}.{l.lower()}{i}@example.org",
            "age": r.randint(18, 79), "pin": r.choice(PINS), "gender": r.choice(["M", "F"]),
            "blood": r.choice(BLOOD), "diagnosis": r.choice(DIAG),
            "note": r.choice(["stable", "follow-up, 2 weeks", "referred", "allergic to penicillin"]),
        })
    # A few awkward cells: an unparseable age, a blank pin, padded text, a quoted comma.
    out[3]["age"] = "n/a"
    out[7]["pin"] = ""
    out[11]["blood"] = " O+ "
    out[13]["note"] = 'said "ok", left'
    # Rare combinations that force generalisation or suppression.
    out[5].update(age=99, pin=560100, blood="AB-", gender="F")
    out[9].update(age=17, pin=560001, blood="AB-", gender="M")
    return out


def write_csv(path, data):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS, lineterminator="\n")
        w.writeheader()
        w.writerows(data)


# Fixed test keys: 64 hex = 32-byte salt, 32 hex = 16-byte key.
KEYS = {
    "tabular_hash_salts.json": {"id": "11" * 32, "phone": "22" * 32},
    "symmetric_keys.json": {"email": "33" * 16},
    "fpe_encrypt_keys.json": {"phone": "44" * 16},
}

BASE = {
    "output_path": "anonymized.csv",
    "suppress": ["name"],
    "hashing_with_salt": ["id"],
    "shared_hash_salts": True,
    "masking": [{"column": "note", "masking_char": "#", "characters_to_mask": [1, 2, 3]}],
    "encrypt": ["email", {"phone": {"format_preserving": True}}],
    "quasi_identifiers": {
        "numerical": [{"column": "age"}, {"column": "pin"}],
        "categorical": [{"column": "gender"}, {"column": "blood"}],
    },
    "size": {"age": 2, "pin": 10},
    "categorical_hierarchies": {
        "blood": {b: [b[:-1], "*"] for b in BLOOD},
        "gender": {"M": ["Any"], "F": ["Any"]},
    },
    "k_anonymize": {"k": 5},
    "suppression_limit": 0.05,
}

CASES_DEF = {
    "basic_pass2": (300, 1, {}),
    "direct_flow": (300, 1, {"flow_mode": "direct"}),
    "original_flow": (300, 1, {"flow_mode": "original"}),
    "tight_limit": (300, 2, {"suppression_limit": 0.02, "k_anonymize": {"k": 8}}),
    "intervals_and_fixed_bins": (300, 3, {
        "qi_constraints": {"age": {"intervals": [{"from": 17, "to": 30}, {"from": 31, "to": 50}, {"from": 51, "to": 70}, {"from": 71, "to": 99}]}},
        "fixed_bins": {"pin": [{"from": 560000, "to": 560050}, {"from": 560051, "to": 560200}]},
        "size": {"age": 2},
    }),
    "l_diversity": (300, 4, {"l_diversity": {"l": 2, "sensitive_attributes": ["diagnosis"]}, "k_anonymize": {"k": 4}}),
    "pass1_grid": (300, 5, {"pass": "pass1", "k_anonymize": None}),
    "chosen_node": (300, 1, {"pass": "pass2", "generalization_node": {"age": 32, "pin": 100, "gender": 1, "blood": 1}}),
    "star_class_removed": (120, 6, {"k_anonymize": {"k": 40}, "suppression_limit": 0.5}),
    "preprocess_only": (60, 7, {"quasi_identifiers": None, "k_anonymize": None, "size": None, "categorical_hierarchies": None}),
}


def main():
    for name, (n, seed, over) in CASES_DEF.items():
        d = os.path.join(CASES, name)
        os.makedirs(os.path.join(d, "testkeys"), exist_ok=True)
        write_csv(os.path.join(d, "data.csv"), rows(n, seed))
        sec = dict(BASE)
        for k, v in over.items():
            if v is None:
                sec.pop(k, None)
            else:
                sec[k] = v
        with open(os.path.join(d, "config.json"), "w") as f:
            json.dump({"data_type": "tabular", "tabular": sec}, f, indent=2)
            f.write("\n")
        for fn, body in KEYS.items():
            with open(os.path.join(d, "testkeys", fn), "w") as f:
                json.dump(body, f, indent=2)
                f.write("\n")


if __name__ == "__main__":
    main()
