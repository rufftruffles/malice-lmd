# malice/lmd

Malice plugin for [rfxn/linux-malware-detect](https://github.com/rfxn/linux-malware-detect)
(LMD / maldet v2.0.1), a signature-based scanner for webshells, backdoors,
and obfuscated payloads on Linux.

## How it works

The Go `scan` binary shells out to the `maldet` CLI (installed at build time):
`maldet -a /malware/<sha256>`, captures the SCANID from the scan output, then
queries `maldet --json-report <SCANID>`. Both steps run inside a single
container invocation because LMD is stateful: its per-scan session files live
under `/usr/local/maldetect/sess` and do not persist across container runs.
The parsed LMD JSON report (schema 1.2) is reduced to a curated subset and
stored as `plugins.av.lmd` in Elasticsearch via the shared
`malice-plugins/pkgs` library (no HTTP API).

Document shape:

```json
{
  "found": true,
  "status": "infected",
  "scan_id": "260904-1928.14",
  "scanner": { "version": "2.0.1", "engine": "native", "hash_type": "sha256", "sig_version": "2026052490478" },
  "total_files": 1,
  "total_hits": 1,
  "hits": [
    { "signature": "{SHA256}bin.backdoor.cobaltstrike.2", "file": "/malware/<sha256>", "hit_type": "SHA256", "hash": "<sha256>", "size": 224768 }
  ],
  "markdown": "#### LMD (Linux Malware Detect)\n..."
}
```

`status` is one of `clean` (no hits), `infected` (hits > 0), `error` (maldet
failed or the report could not be parsed), or `skipped` (sample not staged at
`/malware/<sha256>`, or outside the scan scope so maldet builds an empty file
list). In every case a document is written; the plugin never crashes on a
scan-level failure. `error` carries the failure message in the `error` field.

LMD hit records also carry `hit_type_label`, `quarantined`, `owner`, `group`,
`mode`, and `mtime`; only the fields above are stored, to keep the document
compact.

## Build-time notes

- maldet v2.0.1 is a bash script that depends on the GNU userland (GNU
  `date -d`, `readlink -f`, mawk). Alpine's busybox is hostile to it, so the
  runtime base is `ubuntu:22.04`.
- The v2.0.1 tarball is published as a [GitHub
  release](https://github.com/rfxn/linux-malware-detect/releases/tag/v2.0.1)
  (rfxn.com's "current" tarball is 1.6.6). `install.sh` must be run with bash
  (it uses bashisms). `install.sh` downloads the signature DB from
  `cdn.rfxn.com`, so the build needs network access.
- The core stages samples as root-owned files and the container runs as root,
  so `scan_ignore_root` is forced to `"0"` at build time (the default `"1"`
  would skip every root-owned file and yield an empty scan).
- maldet's default `scan_max_filesize="2048k"` (2MB) is tuned for scanning
  trees of small web files. Malice submits a single sample of arbitrary size,
  and the SHA-256 hash pass should cover the whole file (the hex/CSIG pass is
  already bounded by `scan_hexdepth`=256KB), so the cap is raised to `10240M`
  (10GB) at build time.
- Quarantine is disabled by default (`quarantine_hits="0"`), so a scan never
  mutates the staged sample.

## Build

```
make build && make tag
```
