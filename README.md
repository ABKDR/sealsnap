# SealSnap

Passive snapshots of public web pages, sealed with a SHA-256 manifest that anyone can check later.

[![tests](https://github.com/ABKDR/sealsnap/actions/workflows/tests.yml/badge.svg)](https://github.com/ABKDR/sealsnap/actions/workflows/tests.yml)
[![licence: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![Windows 10 and 11](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-lightgrey.svg)](#install)

[Русская версия](README.ru.md)

## What it does

SealSnap takes a web address, fetches the page under strict network rules, renders it in Microsoft
Edge with scripts switched off and saves the result as a folder of five files. One of them,
`manifest.json`, records the size and SHA-256 hash of the other four. Later the `verify` command
compares the folder with that manifest and rejects it on any mismatch.

It runs on Windows 10 and 11 and uses the Edge that is already installed. A small window covers
everyday use, and the command line covers scripts.

## Why

Lawyers, regulators, researchers and journalists often have to show what a page displayed when they
opened it. A bare screenshot is easy to dispute. SealSnap puts the raw server response, the page as
the browser built it, an image of it and a log of the requests into one package. Later you can show
that none of these files has changed since the capture. If the manifest fingerprint was stored apart
from the package, you can also show that the package as a whole was not swapped for another one.

## How it works

1. The address is checked before any network access. Only `http` and `https` on their default ports
   (80 and 443) are accepted, with no user name or password and at most 4096 characters.
2. The page is fetched by SealSnap itself. The host name is resolved first, and every IPv4 address
   in the DNS answer must be public; a single private or reserved address is enough to refuse. The
   connection goes to the checked address with no second lookup. Every redirect, up to five, is
   checked again from the start. Only GET requests are sent.
3. Edge renders the page passively. It starts headless with its sandbox enabled and a fresh
   temporary profile, and JavaScript is off. The browser has no network of its own. It is set
   offline, and its proxy points to a local server that refuses every request. The page itself is
   handed to Edge from the bytes already fetched. Stylesheets, images and fonts it asks for are
   fetched by SealSnap under the same rules. Every other request is blocked and listed in the
   metadata, up to 100 entries.
4. The original response, the rendered DOM, a PNG screenshot, the metadata and the manifest are
   written to a new folder. SealSnap verifies the finished package once before it reports success.
5. At any later time, `verify` reads the folder again and compares every file with the manifest. It
   never opens the HTML in a browser.

## Package contents

| File | Contents |
|---|---|
| `source.html.txt` | The response body as it came from the server. |
| `rendered.html.txt` | The DOM after passive rendering, in UTF-8. |
| `screenshot.png` | An image 1280 px wide and 900 to 6000 px tall. |
| `metadata.json` | Requested and final URL, HTTP status, server IPv4 address, redirects, requests made, blocked requests, start and finish time in UTC taken from the local clock, Edge version and rendering mode. |
| `manifest.json` | The format tag and the size and SHA-256 of the four files above. |

HTML is stored with a `.txt` extension so that a double click opens it as text instead of loading it
in a browser. Each package folder is named `snapshot-` plus a random identifier, and SealSnap never
overwrites or deletes an existing package. The requested address is saved in the metadata, so avoid
capturing links that carry secret tokens.

## Install

You need Windows 10 or 11, a current Microsoft Edge and Python 3.12 with the `tkinter` module (needed
only for the window). SealSnap does not download a browser; it uses the Edge already installed.

With `uv`, from the project folder:

```powershell
uv venv --python 3.12 .venv
uv pip sync --python .venv/Scripts/python.exe --require-hashes --only-binary :all: requirements.lock
```

With pip, in a Python 3.12 environment:

```powershell
python -m pip install --require-hashes --only-binary :all: -r requirements.lock
```

Every dependency is pinned to an exact version and hash in `requirements.lock`. `START.vbs` looks
for the environment in `.venv` inside the project folder. `pyproject.toml` also declares a
`sealsnap` console command, which becomes available once the project itself is installed into the
environment.

## Use

### Window

Double-click `START.vbs`. The window opens without a terminal. If `.venv` is missing, a message says
so and nothing starts. `python -m sealsnap gui` opens the same window.

Paste the address, choose a folder and press the save button. When the capture finishes, the window
shows the package path and the manifest fingerprint, and the open folder button takes you there. The
verify button checks any package folder. If you kept a fingerprint from an earlier capture, paste it
into the field above that button and the package is checked against it as well. The cancel button,
or closing the window, stops a capture in progress. The window is in Russian for now; an English
interface is the first item on the roadmap.

### Command line

```powershell
python -m sealsnap capture https://example.com --output captures
python -m sealsnap verify captures/snapshot-<id>
python -m sealsnap verify captures/snapshot-<id> --expected-sha256 <fingerprint>
```

Results are printed as JSON. Success exits with code 0 and `ok: true`. An expected refusal, such as
an unsafe address, a limit reached or a file that does not match, exits with code 2 and prints
`ok: false` with a short error code, for example `NON_PUBLIC_ADDRESS` or
`FILE_DIGEST_MISMATCH:source.html.txt`. The `assurance` note in the output is in Russian, like the
window. Without `--output`, packages go to a `captures` folder next to the `sealsnap` module
directory; when you run from a source checkout, that is the project folder.

## What verification proves and does not prove

Verification proves that the four files have exactly the sizes and SHA-256 hashes recorded in
`manifest.json`, that no file is missing or added, and that there are no symbolic links, junctions
or hard links. Without an external fingerprint this is consistency, not authenticity. Whoever
changes a file and rewrites the manifest to match will pass. If the manifest fingerprint was saved
separately at capture time and is passed with `--expected-sha256`, replacing the whole package is
detected too.

It does not prove when the capture was made. The time comes from the local clock and is not
certified, the manifest is not signed, and no timestamp service is used. Nor does it prove who made
the capture, or that other visitors saw the same page. Completeness is not guaranteed either.
Scripts, frames and forms are off, so pages built by scripts may look partial. SealSnap is not a
substitute for notarisation.

## Security model and limits

SealSnap treats the typed address, DNS answers, every HTTP response and redirect, the page content
and any package handed to `verify` as untrusted. The main limits are these.

- Public IPv4 addresses only. Sites reachable only over IPv6 are not supported.
- Ports 80 and 443, GET requests only.
- System proxy settings are not used.
- Compressed responses and attachments (`Content-Disposition: attachment`) are refused.
- A response body may be up to 2 MiB, all responses together up to 16 MiB, with at most 50 requests
  and a network budget of 35 s.
- The whole capture is stopped after 70 s.
- The worker process and everything it starts, Edge included, run in a Windows Job limited to
  1536 MiB of memory, and closing the job ends them all.
- No JavaScript, iframes, forms, WebSocket, service workers, downloads, user profile or cookies.

This is not a virtual machine. An unknown flaw in Edge or Windows is beyond what SealSnap can
contain, so capture pages you expect to be hostile on a separate machine or in a virtual machine. The threat
model and the reporting procedure are in [SECURITY.md](SECURITY.md).

## Roadmap

- English interface.
- Signed manifests and trusted timestamps.
- Batch capture from a list of URLs.
- PDF report for a package.
- Linux support.

## Development

```powershell
python -B -m unittest discover -s tests -v
```

The unit tests need no internet access. Network behaviour is tested against a local fixture server,
and the Windows Job tests run only on Windows. CI runs them on Windows with Python 3.12 in the
`tests` workflow. `tests/gui_smoke.py` drives the real window, goes out to example.com and is run
separately by hand.

SealSnap was developed privately in October 2026; before this first public release it went through
an independent defect review, and the defects found were fixed.

## Security policy

Report vulnerabilities privately through GitHub and not in public issues. Details are in
[SECURITY.md](SECURITY.md).

## Licence

MIT. See [LICENSE](LICENSE). Copyright (c) 2026 Boris Avetisyan.
