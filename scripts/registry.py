#!/usr/bin/env python3
"""Sign, record and lay out RGenomicsETL DuckDB extensions.

Subcommands:
  footer FILE                      print the extension footer as JSON
  prepare --channel C --extension NAME --artifacts DIR --out DIR --key PEM
                                   validate CI artifacts, sign and gzip them
  verify --dist DIR                install the prepared build through DuckDB with signatures on
  record --entry JSON              append a prepared entry to manifest.json
  site --out DIR [--assets DIR]    build the static repository from manifest.json

Signing follows DuckDB's scripts/extension-upload-single.sh: the last 256
bytes (the signature slot) are dropped, the rest is hashed in 1 MiB chunks
(SHA-256 of each chunk, then SHA-256 of the concatenated digests), the digest
is signed with RSA PKCS#1 v1.5 / SHA-256, and the signature is appended.
"""

import argparse
import gzip
import hashlib
import html
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "manifest.json"
KEYS = ROOT / "keys"
CHANNELS = ("dev", "stable")
FOOTER_SIZE = 512
SIGNATURE_SIZE = 256
CHUNK = 1024 * 1024
# wasm builds are resolved against duckdb-wasm's own version directories;
# they are not published until duckdb-wasm supports user repositories.
NATIVE_PLATFORMS = ("linux_amd64", "linux_arm64", "osx_amd64", "osx_arm64",
                    "windows_amd64", "windows_arm64", "windows_amd64_mingw")


def footer(data: bytes) -> dict:
    if len(data) < FOOTER_SIZE:
        raise ValueError("file too small to be a DuckDB extension")
    meta = data[-FOOTER_SIZE:-SIGNATURE_SIZE]
    fields = [meta[i * 32:(i + 1) * 32].rstrip(b"\0").decode() for i in range(8)]
    fields.reverse()  # stored last-field-first
    magic, platform, engine, version, abi = fields[:5]
    if magic != "4":
        raise ValueError("unrecognised extension footer")
    return {"platform": platform, "engine": engine, "extension_version": version, "abi": abi}


def extension_hash(data: bytes) -> bytes:
    digests = b"".join(hashlib.sha256(data[i:i + CHUNK]).digest() for i in range(0, len(data), CHUNK))
    return hashlib.sha256(digests).digest()


def sign(data: bytes, key: Path) -> bytes:
    body = data[:-SIGNATURE_SIZE]
    with tempfile.TemporaryDirectory() as tmp:
        digest = Path(tmp, "digest")
        digest.write_bytes(extension_hash(body))
        signature = subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", str(key), "-pkeyopt", "digest:sha256", "-in", str(digest)],
            check=True, capture_output=True).stdout
    if len(signature) != SIGNATURE_SIZE:
        raise ValueError(f"expected a {SIGNATURE_SIZE}-byte RSA-2048 signature, got {len(signature)}")
    return body + signature


def fingerprint(pem: Path) -> str:
    der = subprocess.run(["openssl", "pkey", "-pubin", "-in", str(pem), "-outform", "DER"],
                         check=True, capture_output=True).stdout
    return "sha256:" + hashlib.sha256(der).hexdigest()


def load_manifest() -> dict:
    return json.loads(MANIFEST.read_text())


def cmd_footer(args):
    print(json.dumps(footer(Path(args.file).read_bytes()), indent=2))


def cmd_prepare(args):
    engines = args.duckdb_versions.split()
    if not engines:
        sys.exit("at least one DuckDB version directory is required")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    platforms, versions = {}, set()
    for path in sorted(Path(args.artifacts).rglob(f"{args.extension}.duckdb_extension")):
        data = path.read_bytes()
        meta = footer(data)
        if meta["platform"] not in NATIVE_PLATFORMS:
            print(f"skip {meta['platform']}: not a native platform", file=sys.stderr)
            continue
        if meta["abi"] == "C_STRUCT_UNSTABLE" and engines != [meta["engine"]]:
            sys.exit(f"{path}: C_STRUCT_UNSTABLE build for {meta['engine']} can only be published under that version")
        if meta["abi"] not in ("C_STRUCT", "C_STRUCT_UNSTABLE"):
            sys.exit(f"{path}: unsupported ABI {meta['abi']}")
        if meta["platform"] in platforms:
            sys.exit(f"duplicate artifact for {meta['platform']}")
        versions.add(meta["extension_version"])
        asset = f"{args.extension}.{meta['platform']}.duckdb_extension.gz"
        with gzip.open(out / asset, "wb", compresslevel=9) as fh:
            fh.write(sign(data, Path(args.key)))
        platforms[meta["platform"]] = {"asset": asset, "abi": meta["abi"], "capi": meta["engine"]}
    if not platforms:
        sys.exit("no native artifacts found")
    if len(versions) != 1:
        sys.exit(f"artifacts disagree on extension version: {sorted(versions)}")
    version = versions.pop()
    entry = {
        "channel": args.channel,
        "extension": args.extension,
        "version": version,
        "tag": f"{args.channel}/{args.extension}/{version}",
        "duckdb_versions": engines,
        "platforms": platforms,
        "key_fingerprint": fingerprint(KEYS / f"{args.channel}.pem"),
        "source": {"repo": args.source_repo, "sha": args.source_sha, "run_id": args.run_id},
    }
    (out / "entry.json").write_text(json.dumps(entry, indent=2) + "\n")
    print(json.dumps(entry, indent=2))


def cmd_verify(args):
    """Install the prepared linux_amd64 build through a real DuckDB 2.0 repository.

    Signature checking stays on: the channel key must accept the build and the
    other channel's key must reject it.
    """
    import duckdb  # the 2.0 pre-release or later, installed by the workflow

    entry = json.loads(Path(args.dist, "entry.json").read_text())
    info = entry["platforms"].get("linux_amd64")
    if info is None:
        sys.exit("verify needs a linux_amd64 build")
    with tempfile.TemporaryDirectory() as tmp:
        probe = duckdb.connect()
        engine = probe.sql("SELECT library_version FROM pragma_version()").fetchone()[0]
        platform = probe.sql("PRAGMA platform").fetchone()[0]
        if platform != "linux_amd64":
            sys.exit(f"verify runs on linux_amd64, not {platform}")
        target = Path(tmp, "repo", engine, platform)
        target.mkdir(parents=True)
        shutil.copyfile(Path(args.dist, info["asset"]), target / f"{entry['extension']}.duckdb_extension.gz")
        prefix = Path(tmp, "repo").as_posix()

        def install(channel_key: str, home: str) -> None:
            con = duckdb.connect(config={
                "allow_unsigned_extensions": "false",
                "allow_extension_repositories": "allowed",
                "extension_directory": str(Path(tmp, home, "extensions")),
                "extension_repository_directory": str(Path(tmp, home, "repositories")),
            })
            key = (KEYS / f"{channel_key}.pem").read_text().replace("'", "''")
            con.sql(f"CREATE EXTENSION REPOSITORY probe WITH PREFIX '{prefix}' USING PUBLIC KEY '{key}'")
            con.sql(f"INSTALL {entry['extension']} FROM probe")

        install(entry["channel"], "accept")
        print(f"{entry['extension']} {entry['version']}: accepted by the {entry['channel']} key on DuckDB {engine}")
        other = next(c for c in CHANNELS if c != entry["channel"])
        try:
            install(other, "reject")
        except duckdb.Error as err:
            print(f"rejected by the {other} key: {str(err).splitlines()[0]}")
        else:
            sys.exit(f"the {other} key accepted a build signed for {entry['channel']}")


def cmd_record(args):
    entry = json.loads(Path(args.entry).read_text())
    manifest = load_manifest()
    if any(e["tag"] == entry["tag"] for e in manifest["releases"]):
        sys.exit(f"{entry['tag']} is already recorded; publish a new extension version instead")
    manifest["releases"].append(entry)
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")


def fetch_asset(entry: dict, asset: str, assets: Path) -> Path:
    local = assets / entry["tag"].replace("/", "__") / asset
    if not local.exists():
        local.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["gh", "release", "download", entry["tag"], "--pattern", asset, "--dir", str(local.parent),
                        "--repo", os.environ.get("GITHUB_REPOSITORY", "RGenomicsETL/duckdb-extensions")], check=True)
    return local


def cmd_site(args):
    out, assets = Path(args.out), Path(args.assets)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    manifest = load_manifest()
    rows = []
    for channel in CHANNELS:
        prefix = out / channel
        (prefix / ".well-known").mkdir(parents=True)
        (prefix / ".well-known" / "duckdb-extension-repo.json").write_text(
            json.dumps({"signature_keys": [(KEYS / f"{channel}.pem").read_text()]}, indent=2) + "\n")
        latest = {}
        for entry in (e for e in manifest["releases"] if e["channel"] == channel):
            latest[entry["extension"]] = entry  # manifest order is publication order
            for platform, info in entry["platforms"].items():
                src = fetch_asset(entry, info["asset"], assets)
                for engine in entry["duckdb_versions"]:
                    dest = prefix / entry["extension"] / entry["version"] / engine / platform
                    dest.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(src, dest / f"{entry['extension']}.duckdb_extension.gz")
        for name, entry in latest.items():
            for platform, info in entry["platforms"].items():
                src = fetch_asset(entry, info["asset"], assets)
                for engine in entry["duckdb_versions"]:
                    dest = prefix / engine / platform
                    dest.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(src, dest / f"{name}.duckdb_extension.gz")
            rows.append((channel, name, entry))
    page = (ROOT / "site" / "index.html").read_text()
    table = "\n".join(
        f"<tr><td>{c}</td><td>{html.escape(n)}</td><td>{html.escape(e['version'])}</td>"
        f"<td>{html.escape(', '.join(e['duckdb_versions']))}</td><td>{html.escape(', '.join(sorted(e['platforms'])))}</td>"
        f"<td><a href=\"https://github.com/{html.escape(e['source']['repo'])}/commit/{html.escape(e['source']['sha'])}\">"
        f"{html.escape(e['source']['sha'][:8])}</a></td></tr>"
        for c, n, e in rows) or '<tr><td colspan="6">Nothing published yet.</td></tr>'
    page = page.replace("{{TABLE}}", table)
    for channel in CHANNELS:
        page = page.replace("{{" + channel.upper() + "_FINGERPRINT}}", fingerprint(KEYS / f"{channel}.pem"))
    (out / "index.html").write_text(page)
    (out / ".nojekyll").write_text("")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("footer"); f.add_argument("file"); f.set_defaults(func=cmd_footer)
    pr = sub.add_parser("prepare")
    pr.add_argument("--channel", choices=CHANNELS, required=True)
    pr.add_argument("--extension", required=True)
    pr.add_argument("--artifacts", required=True)
    pr.add_argument("--out", required=True)
    pr.add_argument("--key", required=True)
    pr.add_argument("--duckdb-versions", required=True, help="space-separated version directories, e.g. 'v2.0.0'")
    pr.add_argument("--source-repo", required=True)
    pr.add_argument("--source-sha", required=True)
    pr.add_argument("--run-id", required=True)
    pr.set_defaults(func=cmd_prepare)
    v = sub.add_parser("verify"); v.add_argument("--dist", required=True); v.set_defaults(func=cmd_verify)
    r = sub.add_parser("record"); r.add_argument("--entry", required=True); r.set_defaults(func=cmd_record)
    s = sub.add_parser("site"); s.add_argument("--out", required=True); s.add_argument("--assets", default=".assets")
    s.set_defaults(func=cmd_site)
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
