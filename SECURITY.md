# Security policy

SKALD de-identifies personal data. A vulnerability in it can re-identify
people in data that has already been released, so please report privately.

## Supported versions

| Version | Supported |
|---|---|
| 4.x | yes |
| 3.x and earlier | no — they contain the defects fixed in 4.0.0 (see `CHANGELOG.md`); upgrade |

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion.**

Report through GitHub's private vulnerability reporting:
**Security → Advisories → Report a vulnerability** on this repository
(<https://github.com/datakaveri/k-anonymisation/security/advisories/new>).

> Maintainers: private vulnerability reporting must be enabled for that link
> to work — repository **Settings → Code security → Private vulnerability
> reporting**. As of October 2026 it is disabled.

Please include:

- The SKALD version (`skald_pipeline --version`) and how you ran it.
- A config and **synthetic** input that reproduce the problem. Never send real
  records, keys, salts or token vaults.
- What an attacker learns or can do, and what they need to know beforehand.

## What to expect

- Acknowledgement within 5 working days.
- An assessment and a fix plan within 30 days. Fixes for anything that can
  re-identify people take priority over all other work.
- Coordinated disclosure: we agree a publication date with you once a fix is
  released. Credit is given unless you ask otherwise.

## In scope

Anything that lets someone learn more from a SKALD release than the configured
protection allows. That includes:

- re-identification despite k-anonymity or l-diversity;
- values released despite a configured technique;
- recovering hashed, tokenised or encrypted values without the key material;
- secrets reaching logs, errors, `status.json` or the release;
- weaknesses in key, salt or token generation.

## Operating SKALD safely

- **Never ship the key directory** (`--keys`, default `<root>/keys`). It holds
  token vaults (originals in clear), encryption keys and hash salts. Ship only
  the output directory. SKALD refuses to run with key material inside it.
- **Restrict the key directory** to the operator (SKALD creates it 0700, files
  0600). Back it up separately; losing it makes earlier pseudonyms
  irreproducible and ciphertexts unrecoverable.
- **Rotate nested-JSON salts generated before 4.0.0.** They were derived from
  the clock and the process id and can be recovered from one known pseudonym.
  The run refuses one (`KEY_MATERIAL_INVALID`) until it is moved away.
- **Review every column**, not just the QIs. The tabular flow releases any
  column no technique names, unchanged.
- **Configure `l_diversity`** whenever the release carries a sensitive
  attribute (diagnosis, scheme, outcome). k-anonymity alone does not stop a
  homogeneous class from disclosing it.
- **Treat configs as code.** A config can point the PostgreSQL connector at
  any host with the credentials it names. Only run configs from people you
  would trust with those credentials.
