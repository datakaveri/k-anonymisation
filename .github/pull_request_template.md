## Summary

<!-- What changes, and why. -->

Closes #

## Privacy impact

- [ ] Does not change what is written to the output, or which records are suppressed / removed
- [ ] …or does, and this PR adds a regression test that fails before the change and passes after
- [ ] No new config key is silently ignored, defaulted or coerced (unknown keys must stay errors)
- [ ] No data value, key, salt or token can reach a log line, error message or `status.json`
- [ ] Config schema / output format changes are recorded in `CHANGELOG.md`

## Checks

- [ ] `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-targets` pass in `SKALD/`
- [ ] No datasets, binaries or key material are committed
