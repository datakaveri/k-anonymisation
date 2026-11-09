# Contributing to SKALD

SKALD decides what personal data leaves an organisation. A bug here can get
real people re-identified. Every change is reviewed with that in mind.

## Branches, tags and pull requests

- **No direct pushes to the default branch.** Every change goes through a pull
  request, merged by squash or merge commit. Force-pushes are blocked.
- **Branch names** must be one of:
  - `<type>/<kebab-case>`, where type is one of `feat`, `fix`, `chore`, `docs`,
    `refactor`, `test`, `perf`, `ci` or `integrate`. Examples:
    `fix/quoted-newline-leak`, `docs/algorithm`.
  - `P3DX-<number>-<description>` for tracked tickets.
  - `release/<version>`.
- **Tags** are `v<major>[.<minor>[.<patch>]]` and immutable. A tag must equal
  the `version` in `SKALD/Cargo.toml`; the release workflow checks this.
- **Never commit** datasets (even "sample" ones that came from real records),
  key material, `output/`, binaries or archives.

## Local checks

Run these from `SKALD/`. The toolchain is pinned by
`SKALD/rust-toolchain.toml`, and rustup installs it on first use.

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo audit                      # cargo install cargo-audit
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
cargo bench --bench ola          # when touching the search or histograms
```

CI runs the same checks on every pull request.

## Changing anonymisation behaviour

Anything that can change what is written, what is suppressed or removed, or
which node OLA-2 picks:

1. **Write the regression test first** — in `SKALD/tests/`, or next to the
   code. Show it **failing before** your change and **passing after**, and say
   so in the PR description.
2. **Never weaken an existing privacy assertion** to make a test pass. If you
   believe it is wrong, raise it in the PR.
3. **A known defect you are not fixing yet** may be committed as a test that
   asserts the correct behaviour, marked
   `#[ignore = "<issue id>: <one line>"]`. CI lists ignored tests, so they stay
   visible. Remove the `#[ignore]` in the PR that fixes it.
4. **Keep fail-closed behaviour.** Fail with a clear error rather than release
   data on:
   - unknown config keys
   - values a technique cannot handle
   - unresolvable columns
   - malformed rows
   - an unavailable RNG
5. **Never log, echo or put in an error message** a data value, key, salt or
   token. Name the column and row instead.
6. **Record config schema or output format changes** in `CHANGELOG.md`, and in
   `README.md` when the guarantee changes.

## Reporting security and privacy problems

Do not open a public issue. See [SECURITY.md](SECURITY.md).
