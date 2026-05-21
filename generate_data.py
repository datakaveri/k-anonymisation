#!/usr/bin/env python3
"""Generate a realistic Indian synthetic profiles dataset for SKALD / SPIDEr testing.

Output schema matches example_spider_config.json:
    QIs        → Age (numerical), Gender (categorical), Blood Group (categorical)
    Sensitive  → Disease
    Suppressed → Customer ID, Full Name, Date of Birth, Email, Phone,
                 Aadhaar, PAN ID, Bank Account Number, IFSC Code,
                 UPI ID, Street Address, PIN Code

Usage:
    python3 generate_data.py                          # 10 000 rows → data/synthetic_profiles.csv
    python3 generate_data.py --rows 50000             # 50 000 rows
    python3 generate_data.py --rows 5000 --seed 0     # reproducible
    python3 generate_data.py --output my_data.csv     # custom output path
"""
from __future__ import annotations

import argparse
import csv
import os
import random
import string
from datetime import date, timedelta
from typing import Tuple


# ─── names & places ─────────────────────────────────────────────────────────

_FIRST_MALE = [
    "Aarav", "Vivaan", "Aditya", "Arjun", "Sai", "Vihaan", "Krishna",
    "Ishaan", "Rohan", "Karthik", "Rahul", "Vikram", "Nikhil", "Pranav",
    "Suresh", "Deepak", "Rajesh", "Amit", "Sandeep", "Manish",
]
_FIRST_FEMALE = [
    "Aanya", "Diya", "Ananya", "Ira", "Meera", "Myra", "Saanvi",
    "Kavya", "Priya", "Nisha", "Pooja", "Rekha", "Sunita", "Geeta",
    "Divya", "Neha", "Swati", "Jaya", "Pallavi", "Sneha",
]
_LAST_NAMES = [
    "Sharma", "Verma", "Reddy", "Patel", "Nair", "Iyer", "Gupta",
    "Singh", "Das", "Joshi", "Pillai", "Mehta", "Bose", "Chatterjee",
    "Mishra", "Tiwari", "Kapoor", "Malhotra", "Rao", "Kumar",
]

_CITY_PINCODES: dict[str, list[int]] = {
    "Mumbai":    [400001, 400002, 400003, 400005, 400006, 400007, 400008, 400009],
    "Delhi":     [110001, 110002, 110003, 110005, 110006, 110007, 110008, 110009],
    "Bengaluru": [560001, 560002, 560003, 560004, 560005, 560006, 560007, 560008],
    "Hyderabad": [500001, 500002, 500003, 500004, 500005, 500012],
    "Chennai":   [600001, 600002, 600003, 600006, 600010, 600020],
    "Kolkata":   [700001, 700002, 700003, 700012, 700020, 700027],
    "Pune":      [411001, 411002, 411004, 411014, 411016, 411030],
    "Ahmedabad": [380001, 380005, 380006, 380007, 380008, 380009],
    "Jaipur":    [302001, 302002, 302003, 302006, 302011, 302018],
    "Lucknow":   [226001, 226002, 226003, 226007, 226010, 226016],
}
_CITIES = list(_CITY_PINCODES.keys())

_STREET_TYPES = ["MG Road", "Nehru Street", "Temple Road", "Market Lane",
                 "Gandhi Nagar", "Station Road", "Civil Lines", "Park Street"]

# ─── medical / demographic distributions ────────────────────────────────────

_BLOOD_GROUPS = ["A+", "O+", "B+", "AB+", "A-", "B-", "O-", "AB-"]
_BLOOD_WEIGHTS = [0.25, 0.28, 0.18, 0.08, 0.06, 0.06, 0.06, 0.03]

_GENDER_VALUES = ["Male", "Female", "Other"]
_GENDER_WEIGHTS = [0.49, 0.49, 0.02]

# Disease pool keyed by age bracket — preserves realistic age-disease correlation
_DISEASE_BY_AGE: dict[str, list[str]] = {
    "young":  ["Healthy", "Healthy", "Asthma", "Migraine", "Healthy"],
    "middle": ["Healthy", "Thyroid", "Hypertension", "Diabetes", "Healthy"],
    "senior": ["Diabetes", "Hypertension", "Arthritis", "Heart Disease", "Healthy"],
}

_EMAIL_DOMAINS = ["gmail.com", "yahoo.com", "outlook.com", "rediffmail.com"]
_UPI_PROVIDERS = ["oksbi", "okhdfcbank", "okaxis", "ybl", "paytm", "ibl"]


# ─── generators ─────────────────────────────────────────────────────────────

def _full_name(gender: str) -> str:
    if gender == "Male":
        first = random.choice(_FIRST_MALE)
    elif gender == "Female":
        first = random.choice(_FIRST_FEMALE)
    else:
        first = random.choice(_FIRST_MALE + _FIRST_FEMALE)
    return f"{first} {random.choice(_LAST_NAMES)}"


def _clustered_age() -> int:
    """Skew towards working-age population for realistic k-anonymity bins."""
    r = random.random()
    if r < 0.15:
        return random.randint(18, 24)
    elif r < 0.40:
        return random.randint(25, 35)
    elif r < 0.65:
        return random.randint(36, 50)
    elif r < 0.85:
        return random.randint(51, 65)
    else:
        return random.randint(66, 85)


def _dob_from_age(age: int) -> str:
    today = date.today()
    birth_year = today.year - age
    try:
        return date(birth_year, random.randint(1, 12), random.randint(1, 28)).strftime("%d-%m-%Y")
    except ValueError:
        return date(birth_year, 1, 1).strftime("%d-%m-%Y")


def _blood_group() -> str:
    return random.choices(_BLOOD_GROUPS, weights=_BLOOD_WEIGHTS, k=1)[0]


def _disease(age: int) -> str:
    if age < 35:
        pool = _DISEASE_BY_AGE["young"]
    elif age < 55:
        pool = _DISEASE_BY_AGE["middle"]
    else:
        pool = _DISEASE_BY_AGE["senior"]
    return random.choice(pool)


def _city_and_pin(prev_city: str | None) -> Tuple[str, int]:
    # 60 % chance of reusing the previous city (creates locality clusters
    # which are good for k-anonymity structure)
    if prev_city and random.random() < 0.60:
        return prev_city, random.choice(_CITY_PINCODES[prev_city])
    city = random.choice(_CITIES)
    return city, random.choice(_CITY_PINCODES[city])


def _email(full_name: str, idx: int) -> str:
    base = "".join(ch for ch in full_name.lower() if ch.isalpha())[:10]
    return f"{base}{idx}@{random.choice(_EMAIL_DOMAINS)}"


def _phone() -> str:
    return "+91-" + "".join(random.choices(string.digits, k=10))


def _aadhaar() -> str:
    return "".join(random.choices(string.digits, k=12))


def _pan() -> str:
    alpha = string.ascii_uppercase
    return (
        "".join(random.choices(alpha, k=5))
        + "".join(random.choices(string.digits, k=4))
        + random.choice(alpha)
    )


def _bank_account() -> str:
    return "".join(random.choices(string.digits, k=random.randint(12, 16)))


def _ifsc() -> str:
    return (
        "".join(random.choices(string.ascii_uppercase, k=4))
        + "0"
        + "".join(random.choices(string.digits, k=6))
    )


def _upi(name: str) -> str:
    base = "".join(ch for ch in name.lower() if ch.isalpha())[:8]
    suffix = "".join(random.choices(string.digits, k=random.randint(2, 5)))
    return f"{base}{suffix}@{random.choice(_UPI_PROVIDERS)}"


def _address(city: str) -> str:
    return (
        f"House {random.randint(1, 999)}, "
        f"{random.choice(_STREET_TYPES)}, {city}"
    )


# ─── main generation ────────────────────────────────────────────────────────

_FIELDNAMES = [
    "Customer ID", "Full Name", "Gender", "Age", "Blood Group",
    "PIN Code", "Date of Birth", "Email", "Phone", "Aadhaar",
    "PAN ID", "Bank Account Number", "IFSC Code", "UPI ID",
    "Street Address", "Disease",
]


def generate(n_rows: int, output_path: str, seed: int = 42) -> None:
    """Generate n_rows synthetic Indian profiles and write to output_path.

    Args:
        n_rows: Number of records to generate.
        output_path: Destination CSV file path.
        seed: Random seed for reproducibility.
    """
    random.seed(seed)
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    prev_city: str | None = None

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_FIELDNAMES)
        writer.writeheader()

        for i in range(1, n_rows + 1):
            gender = random.choices(_GENDER_VALUES, weights=_GENDER_WEIGHTS, k=1)[0]
            age = _clustered_age()
            city, pin = _city_and_pin(prev_city)
            prev_city = city
            full_name = _full_name(gender)

            writer.writerow({
                "Customer ID":        f"CUST{i:07d}",
                "Full Name":          full_name,
                "Gender":             gender,
                "Age":                age,
                "Blood Group":        _blood_group(),
                "PIN Code":           pin,
                "Date of Birth":      _dob_from_age(age),
                "Email":              _email(full_name, i),
                "Phone":              _phone(),
                "Aadhaar":            _aadhaar(),
                "PAN ID":             _pan(),
                "Bank Account Number": _bank_account(),
                "IFSC Code":          _ifsc(),
                "UPI ID":             _upi(full_name),
                "Street Address":     _address(city),
                "Disease":            _disease(age),
            })

    print(f"Generated {n_rows:,} rows → {output_path}")


# ─── CLI ────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a synthetic Indian profiles dataset for SPIDEr / SKALD testing."
    )
    parser.add_argument(
        "--rows", type=int, default=10_000,
        help="Number of records to generate (default: 10 000).",
    )
    parser.add_argument(
        "--output", default="data/synthetic_profiles.csv",
        help="Output CSV path (default: data/synthetic_profiles.csv).",
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for reproducibility (default: 42).",
    )

    args = parser.parse_args()
    generate(n_rows=args.rows, output_path=args.output, seed=args.seed)


if __name__ == "__main__":
    main()
