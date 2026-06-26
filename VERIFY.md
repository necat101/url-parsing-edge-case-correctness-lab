# VERIFY.md — Fresh-clone verification

Verified commit: `4de259e581692c0d4c516906862b342db3b7983c`

```bash
$ git clone https://github.com/necat101/url-parsing-edge-case-correctness-lab.git url-verify
Cloning into 'url-verify'...

$ cd url-verify
$ python3 -m py_compile generate_cases.py run_lab.py
$ python3 generate_cases.py
Wrote 50 cases to cases/cases.jsonl (25423 bytes)

$ python3 run_lab.py
Results: results/results.jsonl (139306 bytes)
Report: RESULTS.md
  urllib_urlsplit_baseline: pass=50 fail=0 skip=0 time=3.04ms
  urllib_urlparse_baseline: pass=50 fail=0 skip=0 time=3.09ms
  parse_qsl_query_decoder: pass=50 fail=0 skip=0 time=3.12ms
  naive_split_scheme_host_path: pass=46 fail=4 skip=0 time=0.37ms
  naive_at_host_detector: pass=40 fail=10 skip=0 time=0.45ms
  idna_codec_demo: pass=39 fail=0 skip=11 time=28.98ms
  ipaddress_host_check: pass=8 fail=0 skip=42 time=2.83ms
```

All 50 cases generated deterministically (seed 42). All stdlib methods pass 100%. Naive methods fail as expected on ambiguous, userinfo, IPv6, unicode, non_http_scheme, and malicious_looking cases.

Python: CPython 3.12.3 on Linux-6.17.0-1009-aws-x86_64-with-glibc2.39
