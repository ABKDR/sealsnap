# Security policy

SealSnap fetches pages from the open web and checks packages that may come from anyone. This file
explains how to report a security problem and what happens after you do.

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x | Yes |
| 0.1.x | No |

Security fixes are made for the latest 0.2.x release.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub. Open the Security tab of
https://github.com/ABKDR/sealsnap and choose Report a vulnerability. Please do not open a public
issue, pull request or discussion for a security problem.

A useful report includes:

- the SealSnap version, the Windows version and the Edge version;
- the exact command or window action and the URL or package that triggers the problem;
- what happened and what you expected instead;
- the impact as you see it, for example which boundary is crossed;
- a minimal reproduction, such as a small test server or a crafted package, if you have one.

## Response

- Receipt of the report is acknowledged within 7 days.
- An assessment and a plan for the fix follow within 30 days.
- If the problem is confirmed, a security advisory is published on GitHub, a CVE is requested
  through GitHub, and the reporter is credited unless they ask not to be named.

## Scope

These count as vulnerabilities:

- crossing the network boundary, for example reaching a private, loopback, link-local, multicast or
  reserved address, an IPv6 address, a port other than 80 or 443, a scheme other than `http` or
  `https`, or an address other than the one that was checked;
- `verify` reading or following anything outside the package folder;
- getting past a size, count, time or memory limit in a way that causes real harm, such as
  exhausting memory or disk;
- errors in TLS certificate or host name verification;
- code execution caused by page content, by a package passed to `verify` or by anything else on the
  capture or verification path;
- `verify` accepting a package whose files do not match its manifest, or a manifest that does not
  match the expected fingerprint.

These do not:

- limits documented as intentional in README.md and in this file, such as the unsigned manifest,
  time taken from the local clock, passive rendering, the lack of IPv6 support, or replacement of
  the whole package together with its manifest when no fingerprint was stored separately;
- scenarios that assume the operating system, Edge or Python is already compromised;
- attacks by another process running with the same user rights;
- pages that look incomplete because they need JavaScript.

## Threat model

Trusted: the operating system, an up-to-date Microsoft Edge, Python and the SealSnap code with its
pinned dependencies.

Untrusted: the URL typed by the user, DNS answers, HTTP responses and redirects, page content (HTML,
CSS, images and fonts) and any package handed to `verify`.

Not isolated: a process running with the same user rights. It can change files, the interpreter or
the operating system while SealSnap works, and this version does not defend against it. `verify`
does notice a file that changes while it is being read.

The boundaries are enforced as follows.

- Network. Every IPv4 answer from DNS must be a public address, and the connection goes to the
  checked address without a second lookup. Redirects, up to five, are checked again. Only `http` on
  port 80 and `https` on port 443 are allowed, with GET requests and no credentials in the URL.
  HTTPS verifies the certificate chain and the host name against the system store plus the `certifi`
  root bundle. Compressed responses, attachments, ambiguous HTTP framing and oversized headers are
  refused.
- Browser. Edge gets data only through request interception. It is set offline, its proxy is a local
  server that refuses every request, its sandbox is enabled explicitly, and it is started with
  `--disable-quic` and `--disable-background-networking`. JavaScript, service workers and downloads are disabled, WebSocket
  connections, pop-ups and dialogs are closed, and the main document is served with a sandboxing
  Content Security Policy. The user profile and its cookies are not used.
- Process. Capture runs in a separate worker started from the base Python interpreter in isolated
  mode with a reduced environment. The worker waits until it is inside a Windows Job before it loads
  the browser driver. The job limits the worker and all its children, Edge included, to 1536 MiB of
  memory and ends them all when it closes. The whole operation is limited to 70 s and can be
  cancelled.
- Package. File names are fixed, files are created exclusively, and the package is verified before
  success is reported. If saving fails, only the files created by that run are removed.
- Verification. The file set must match exactly. Symbolic links, junctions and hard links are
  refused, and so are duplicate JSON keys, non-finite numbers, schema deviations, files over their
  size limit and any size or hash mismatch. HTML is never opened as an active page.

Without a trusted external fingerprint, verification shows that the files are consistent with each
other. It does not show that they are authentic. Even with a fingerprint it does not prove the real
time of capture, the truth of the content or who owns the site. The manifest is not signed and no
timestamp service is called.

## Disclosure policy

SealSnap follows coordinated disclosure. Please allow up to 90 days from your report before
publishing details. The advisory is normally published together with the fix; if a fix needs more
time, a new date is agreed with the reporter.

## Security maintainer

Boris Avetisyan. Contact goes through the private reporting channel described above.
