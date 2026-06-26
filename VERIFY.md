# VERIFY.md — Fresh-clone verification

## Commit 8dcb27b (HEAD)

Verified 2026-06-26.

```bash
$ git clone https://github.com/necat101/url-parsing-edge-case-correctness-lab.git url-verify
Cloning into 'url-verify'...

$ cd url-verify
$ python3 -m py_compile generate_cases.py run_lab.py
$ python3 generate_cases.py
Wrote 50 cases to cases/cases.jsonl (25423 bytes)

$ python3 run_lab.py
Results: results/results.jsonl (139312 bytes)
Report: RESULTS.md
  urllib_urlsplit_baseline: pass=50 fail=0 skip=0 time=2.93ms
  urllib_urlparse_baseline: pass=50 fail=0 skip=0 time=3.07ms
  parse_qsl_query_decoder: pass=50 fail=0 skip=0 time=3.13ms
  naive_split_scheme_host_path: pass=46 fail=4 skip=0 time=0.38ms
  naive_at_host_detector: pass=40 fail=10 skip=0 time=0.45ms
  idna_codec_demo: pass=39 fail=0 skip=11 time=26.25ms
  ipaddress_host_check: pass=8 fail=0 skip=42 time=4.45ms
```

All 50 cases generated deterministically (seed 42).
- `urllib_urlsplit_baseline`, `urllib_urlparse_baseline`, `parse_qsl_query_decoder`: **50/50 pass, 0 skip**.
- `idna_codec_demo`: 39 pass, 0 fail, 11 skip (IP literals / no-host cases skipped by design).
- `ipaddress_host_check`: 8 pass, 0 fail, 42 skip (non-IP hosts skipped by design).
- Naive methods fail as expected on ambiguous, userinfo, IPv6, unicode, non_http_scheme, and malicious_looking cases.

Python: CPython 3.12.3 on Linux-6.17.0-1009-aws-x86_64-with-glibc2.39

---

## Prior verifications

- Commit `5e7cad7` — also fresh-clone verified with identical results.
- Commit `d4de2ec` — code cleanup + README clarification; also fresh-clone verified with identical results.
- Commit `4de259e` — initial results commit; fresh-clone verified before VERIFY.md was added in commit `a48d485`.
