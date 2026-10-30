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

- builtin: `https://grype.anchore.io/databases/v6/latest.json` (the listing)
  and the archive it names, which Grype resolves against the same host, to
  download the vulnerability database on first use and, at most
  once every `db_update_check_interval` (default 2h), to check for and
  download a newer build. The database is stored under the OS cache directory
  (`grype/db`) or `db_dir`. When it cannot be refreshed, the matcher keeps
  matching against the local copy and warns once the copy is older than
  `db_max_age` (default five days), because every advisory published since
  is missing from that run. `db_auto_update: false` skips the check entirely.
  The download goes through Grype's own HTTP client, which honors the
  standard `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` variables rather than
  Bomly's proxy settings.
- external: whatever the installed `grype` binary itself does (typically the
  same database service).

## Upstream

The builtin variant compiles in Anchore's Grype and Syft, both Apache-2.0,
and depends on Anchore's hosted database, which publishes no terms or rate
limits. Two tests in `plugin/upstream_test.go` fail a dependency bump that
would change that silently:

- `TestUpstreamLicensesAreUnchanged` fails when either library's `LICENSE`
  file changes, so a relicense is read before it ships.
- `TestGrypeVersionMeetsSchemaFloor` fails a Grype older than the oldest
  version whose database schema Anchore still serves (`minGrypeVersion`).
  Such a Grype does not error; it finds nothing. Raise the floor when Anchore
  announces the next schema end of life.

If the hosted database stops being available, it can be rebuilt from public
sources with Anchore's [vunnel](https://github.com/anchore/vunnel) and
[grype-db](https://github.com/anchore/grype-db), both Apache-2.0. Expect
hours, about 8 GB, and a GitHub token for the advisory API's rate limits.
Build it for schema 6: that is the only schema this matcher reads, and it
finds a database only under `<db_dir>/6`. Install the archive into the matcher's database directory with
`GRYPE_DB_CACHE_DIR=<db_dir> grype db import <archive>`, then set
`db_auto_update: false` so the matcher stops asking the hosted service.

## Access

`bomly-plugin.json` declares what the matcher touches, which Bomly shows when you install it and in `bomly plugin info`. It is a disclosure, not a sandbox. It describes the builtin variant, which is what the release archives ship.

| Access | Why |
| --- | --- |
| Reads and writes `cache` | The vulnerability database, `<user cache dir>/grype/db` by default, and the scratch directory each download unpacks into there |
| Reads `home` | On Linux, the XDG library Grype links reads `~/.config/user-dirs.dirs` when the process starts |
| Reads and writes `temp` | The database listing and the downloaded archive, written there and read back while it is unpacked |
| Network `grype.anchore.io` | The database listing and archive |
| Environment `HOME`, `XDG_*`, `LocalAppData`, `USERPROFILE` | Locating the cache: `os.UserCacheDir` reads `XDG_CACHE_HOME` and `HOME` (`LocalAppData` on Windows), and the XDG library reads `HOME` and every `XDG_*` base directory when it starts, falling back to `USERPROFILE` on Windows |
| Environment `TMPDIR`, `TMP`, `TEMP` | `os.TempDir`, for the temporary files above (`TMPDIR` on Unix, `TMP` or `TEMP` on Windows) |
| Environment `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` (and lower case), `REQUEST_METHOD` | Grype's download client uses Go's standard proxy lookup, which reads these |

Setting `db_dir` moves the database to a place you chose; the declaration describes the default. `db_auto_update: false` stops the network access and the temporary files. The external variant starts `grype` instead, and its access is whatever that binary does. The matcher needs no particular pipeline input beyond the packages it is asked to match, so it declares no requirements.

## Configuration

Embedded execution is configured by the Bomly CLI (it constructs
`Matcher{Logger: ...}` directly). Managed execution reads a JSON block under
`plugins.matchers.grype`:

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `db_dir` | string | OS cache dir + `/grype/db` | Grype vulnerability DB directory (builtin variant) |
| `db_auto_update` | bool | `true` | Check Grype's distribution service for a newer database and download it (builtin variant); `false` uses the local copy as it is and fails when there is none |
| `db_max_age` | duration | `120h` | Age past which the matcher warns that its database is stale (builtin variant) |
| `db_update_check_interval` | duration | `2h` | Minimum time between update checks (builtin variant) |

Durations use Go syntax (`30m`, `48h`); there is no day unit, so five days is
`120h`. Embedded in the Bomly CLI, the same three settings are exposed as
`matchers.grype.*` configuration keys.

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
