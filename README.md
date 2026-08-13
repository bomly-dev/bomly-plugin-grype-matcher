# bomly-plugin-grype-matcher

Grype vulnerability matcher for [Bomly](https://github.com/bomly-dev/bomly-cli).

It matches packages in a Bomly scan against the
[Grype](https://github.com/anchore/grype) vulnerability database, attaching
advisories with severity, CVSS, EPSS, KEV, CWE, and fix data.

> **Already inside the Bomly CLI.** This matcher ships embedded in the `bomly`
> binary as the built-in `grype` matcher — you do not need to install this
> plugin to use Grype enrichment. This repository is the matcher's home as a
> standalone module: the Bomly CLI consumes the same code in-process, and the
> plugin binary serves it to hosts that run matchers as managed subprocesses.

## Identity

- Plugin id / descriptor name: `grype`
- Kind: matcher
- Module path: `github.com/bomly-dev/bomly-plugin-grype-matcher`

## Build variants

Two build-tag variants exist, mirroring the Bomly CLI's full and lite builds:

- **builtin** (default, no tags): vendors the Grype Go libraries and matches
  in-process against a locally managed copy of the Grype DB.
- **external** (`-tags bomly_external_grype`): shells out to a `grype` CLI
  binary found on `PATH`, feeding it the dependency graph as SPDX JSON on
  stdin. Requires no vendored DB but does require the binary.

CI tests both variants. Release archives ship the builtin variant.

## Network behavior

This matcher performs network calls **only during enrichment** (`bomly scan
--enrich`), never during audit-only runs:

- builtin: `https://grype.anchore.io/databases` (plus the archive URL it
  returns) to download and refresh the vulnerability database, stored under
  the OS cache directory (`grype/db`) or `db_dir`.
- external: whatever the installed `grype` binary itself does (typically the
  same database service).

## Configuration

Embedded execution is configured by the Bomly CLI (it constructs
`Matcher{Logger: ...}` directly). Managed execution reads a JSON block under
`plugins.matchers.grype`:

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `db_dir` | string | OS cache dir + `/grype/db` | Grype vulnerability DB directory (builtin variant) |

## Package-updates delta protocol: not adopted

This matcher deliberately does **not** advertise `package-updates-v1`. It
merges a new advisory into an existing vulnerability with the same
`(Source, ID)` field by field — filling empty scalars and unioning CVSS
scores, references, aliases, EPSS, CWE, and fix data. `Package.MergeFrom`
cannot express that: when a delta carries a vulnerability whose `(Source, ID)`
already exists on the target package, it only fills reachability data and
drops every other enrichment. Until the host merge grows field-level
vulnerability merging, only the in-place registry path preserves this
matcher's semantics. `TestDescriptorDoesNotAdvertisePackageUpdates` pins the
decision.

## Development

```sh
make test                              # builtin variant
go test -tags bomly_external_grype ./...  # external variant
make build                             # build bin/bomly-plugin-grype-matcher
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
