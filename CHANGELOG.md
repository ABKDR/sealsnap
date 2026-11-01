# Changelog

All notable changes to SealSnap are recorded in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and version numbers follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 (2026-11-01)

First public release. SealSnap was developed privately in October 2026; before this release it went
through an independent defect review, and the defects found were fixed.

### Added

- `capture` takes a passive snapshot of a public `http` or `https` page and writes it to a new
  package folder.
- `verify` checks a package strictly against its manifest and, with `--expected-sha256`, against a
  manifest fingerprint stored elsewhere.
- `gui` and the `START.vbs` launcher open a desktop window for capture and verification without a
  terminal. The window text is in Russian.
- Package format `sealsnap-1` with five files: `source.html.txt`, `rendered.html.txt`,
  `screenshot.png`, `metadata.json` and `manifest.json`.
- Screenshots 1280 px wide and 900 to 6000 px tall.
- Metadata with the requested and final URL, HTTP status, server IPv4 address, redirects, requests,
  blocked requests, start and finish time in UTC from the local clock, Edge version and rendering
  mode.
- JSON output on the command line, with exit code 0 on success and 2 on an expected refusal.
- Dependencies pinned by version and hash in `requirements.lock`.
- Unit tests for URL and address rules, HTTP framing and limits, package verification and the
  Windows Job, run in CI on Windows with Python 3.12.

### Security

- A guarded HTTP client: public IPv4 addresses only, every DNS answer checked before connecting,
  connection to the checked address with no second lookup, each redirect checked again (up to 5),
  ports 80 and 443, GET only, TLS verification of the certificate chain and host name.
- Refusal of compressed responses, attachments, ambiguous HTTP framing and oversized headers.
- Limits of 2 MiB per response, 16 MiB in total, 50 requests, a 35 s network budget and 70 s for the
  whole operation.
- Passive rendering in the installed Microsoft Edge: headless, sandbox enabled, offline, behind a
  local proxy that refuses everything, with no JavaScript, iframes, forms, WebSocket, service
  workers, downloads, user profile or cookies.
- A separate worker process inside a Windows Job with a 1536 MiB memory limit; closing the job ends
  the whole process tree.
- Strict verification: exact file set, no symbolic links, junctions or hard links, no duplicate JSON
  keys, size limits per file, matching sizes and SHA-256 hashes, and a check of the PNG header and
  dimensions.
- HTML stored as `.txt` and never opened as an active page.

### Known limitations

- Windows 10 and 11 with Microsoft Edge only.
- Pages built by JavaScript may be captured incompletely.
- No IPv6, no ports other than 80 and 443, no system proxy.
- The manifest is not signed, and the capture time comes from the local clock without certification.
- Without a separately stored manifest fingerprint, replacing the whole package together with its
  manifest is not detected.
- Isolation rests on the browser sandbox and the Windows Job; it is not a virtual machine.
- The window and part of the command line output are in Russian.

Security problems in this release are reported through the private channel described in
[SECURITY.md](SECURITY.md).
