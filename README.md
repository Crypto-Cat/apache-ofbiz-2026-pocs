# Apache OFBiz 2026 PoCs

Proof-of-concept scripts accompanying seven Apache OFBiz writeups reported in August 2026, all fixed in Apache OFBiz 24.09.08.

| Script | CVE | Finding | Access | Severity | Writeup |
| --- | --- | --- | --- | --- | --- |
| [`cve_2026_73577.py`](cve_2026_73577.py) | CVE-2026-73577 | Path-suffix view authorization bypass to RCE | Unauthenticated | Important | [Writeup](https://cryptocat.me/blog/research/analysis/cve_2026_73577/) |
| [`cve_2026_73578.py`](cve_2026_73578.py) | CVE-2026-73578 | Saved-view authorization bypass to RCE | Unauthenticated | Important | [Writeup](https://cryptocat.me/blog/research/analysis/cve_2026_73578/) |
| [`cve_2026_82894.py`](cve_2026_82894.py) | CVE-2026-82894 | `showHelpPublic` private Content disclosure (advisory covers the `Content.serviceName` service-invocation root) | Unauthenticated read; CONTENTMGR_CREATE/UPDATE to arm the service root | Important | [Writeup](https://cryptocat.me/blog/research/analysis/cve_2026_82894/) |
| [`cve_2026_83538.py`](cve_2026_83538.py) | CVE-2026-83538 | Unauthenticated disclosure via HR, Catalog and Order Manager helper routes | Unauthenticated | Moderate | [Writeup](https://cryptocat.me/blog/research/analysis/cve_2026_83538/) |
| [`cve_2026_83542.py`](cve_2026_83542.py) | CVE-2026-83542 | Widget-resource injection RCE | Unauthenticated | Critical | [Writeup](https://cryptocat.me/blog/research/analysis/cve_2026_83542/) |
| [`cve_2026_84183.py`](cve_2026_84183.py) | CVE-2026-84183 | Content Manager VIEW-only RCE via `updateLayout` | OFBTOOLS_VIEW + CONTENTMGR_VIEW | Important | [Writeup](https://cryptocat.me/blog/research/analysis/cve_2026_84183/) |
| [`cve_2026_84728.py`](cve_2026_84728.py) | CVE-2026-84728 | Cross-tenant authorization bypass in mapped-domain login | Low-privilege account in any tenant | Important | [Writeup](https://cryptocat.me/blog/research/analysis/cve_2026_84728/) |

Each script needs Python 3 and `requests` (`pip install requests`), writes coloured progress to stderr and results to stdout, honours `NO_COLOR`, and takes `--no-color` and (for the HTTPS targets) `--verify-tls`. Run only against systems you are authorised to test.

```bash
python3 cve_2026_73577.py https://target:8443 -c id --fd-min 200 --fd-max 600
python3 cve_2026_73578.py https://target:8443 -c id --fd-min 200 --fd-max 600
python3 cve_2026_82894.py https://target:8443 SEC-PRIVATE-CONT
python3 cve_2026_83538.py https://target:8443 hr Company
python3 cve_2026_83542.py https://target:8443 -c id --carrier portal --fd-min 250 --fd-max 350
python3 cve_2026_84183.py https://target:8443 USER 'PASS' RESPONSE_CONTENT_ID DATA_RESOURCE_ID -c id
python3 cve_2026_84728.py https://target:8443 USER 'PASS' ATTACKER_TENANT_ID --party-id VICTIM_PARTY_ID
```

The RCE chains (73577, 73578, 83542) stage a widget document inside a live multipart upload and read it back through a Linux process descriptor, so they need a Linux target that streams request bodies to a single OFBiz JVM. TLS verification is off by default because OFBiz ships self-signed certificates; pass `--verify-tls` where appropriate.

Affected: Apache OFBiz 24.09 before 24.09.08. Fixed in 24.09.08.
