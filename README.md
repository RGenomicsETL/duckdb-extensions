# RGenomicsETL DuckDB extensions

Signed builds of [RGenomicsETL](https://github.com/RGenomicsETL) DuckDB extensions, served as
DuckDB [external extension repositories](https://github.com/duckdb/duckdb/pull/24777)
(DuckDB 2.0 and later) from <https://rgenomicsetl.github.io/duckdb-extensions/>.

## Use

```sql
SET allow_extension_repositories = 'allowed';
CREATE EXTENSION REPOSITORY rgenomicsetl
  WITH PREFIX 'https://rgenomicsetl.github.io/duckdb-extensions/stable';
INSTALL AND LOAD duckhts FROM rgenomicsetl;
```

`CREATE EXTENSION REPOSITORY` fetches the channel's public key and prints its fingerprint.
Compare it with the table below; to skip the fetch, pass the key from [`keys/`](keys) with
`USING PUBLIC KEY '...'`. From R, pass `config = list(allow_extension_repositories = "allowed")`
to `duckdb::duckdb()`.

| Channel | Prefix | Carries | Key fingerprint |
|:--|:--|:--|:--|
| `stable` | `https://rgenomicsetl.github.io/duckdb-extensions/stable` | releases that also went to CRAN and the DuckDB community repository | `sha256:c11997ddf402e763899c49ef98a2d6baadf726ab5dac8ecfbf7c3f561da86652` |
| `dev` | `https://rgenomicsetl.github.io/duckdb-extensions/dev` | builds from each project's main branch | `sha256:4e6e3fd190e775be1edd33003c3966f6fe5bd6312dfb1ca4d4ecabe7c65c9335` |

Every published build stays installable by version. DuckDB keeps one installed copy per
extension, so switch versions with `FORCE INSTALL duckhts VERSION '1.5.2.9003' FROM rgenomicsetl`
and load it in a fresh database instance.

## How it works

- [`manifest.json`](manifest.json) records every publication: channel, extension version,
  DuckDB version directories, platforms, source commit and CI run, and signing-key fingerprint.
- The **Publish extension** workflow takes a successful CI run from an extension repository,
  checks each binary's footer (platform, ABI, extension version), signs it with the channel key
  exactly as DuckDB's own `extension-upload-single.sh` does, stores the signed binaries as a
  release here and appends to the manifest. Stable publications must come from a tagged commit.
- The **Pages** workflow lays the manifest out as DuckDB expects:
  `<channel>/<duckdb version>/<platform>/<name>.duckdb_extension.gz` for the latest build and
  `<channel>/<name>/<version>/<duckdb version>/<platform>/…` for every build, plus
  `<channel>/.well-known/duckdb-extension-repo.json`.

Only native platforms are published. duckdb-wasm resolves extensions against its own version
directories and is not yet covered.

Each channel's private key is an Actions secret (`SIGNING_KEY`) of the matching GitHub
environment (`dev`, `stable`), with an offline copy kept by the maintainer. Before any binary is
stored, the workflow installs the signed Linux build through DuckDB 2.0 with signature checking
on, and checks that the other channel's key rejects it.

DuckDB pins a repository's keys when it is registered and never refetches them, so rotating a
key means publishing the new key alongside the old one, announcing its fingerprint, and asking
users to re-register the repository (`DROP EXTENSION REPOSITORY` then `CREATE`) during an
overlap period before builds are signed with the new key only.
