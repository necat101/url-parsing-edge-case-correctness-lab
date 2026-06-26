# URL Parsing Edge-Case Correctness Lab

A tiny, reproducible Python-only lab testing the Hacker News debate around URL parsing in Python.

**HN thread:** https://news.ycombinator.com/item?id=39727458
**Linked article:** https://tkte.ch/articles/2024/03/15/parsing-urls-in-python.html

## What HN was debating

- URL parsing looks simple but gets complicated fast.
- WHATWG browser behavior and RFC 3986-style parsing are **not** the same thing.
- `urllib.parse` is stable and useful but not a modern universal URL oracle — it predates WHATWG and retains quirks for backward compatibility (Hyrum's Law).
- Changing parsers can create **parser-differential bugs** — the same URL parsed differently by two libraries.
- Userinfo (`user:pass@host`), fragments, IPv6 brackets, weird slashes, Unicode, IDNA/Punycode, path normalization, and percent-encoding all matter.
- Naive host extraction is dangerous for allowlists or SSRF-style checks.
- Performance claims are less important than extracting the right security-relevant fields.
- Projects like **can_ada** / Ada, yarl, hyperlink, and httpx are related ecosystem context but out of scope for this tiny lab.

See the article for details on Ada (WHATWG-compliant, fast C++) and can_ada (pybind11 Python bindings, ~2× faster than ada-python, ~4.6× faster than urllib.parse).

## What this lab does

Tests 50 deterministic URL edge cases across 7 stdlib-only methods:

| Method | Description |
|---|---|
| `urllib_urlsplit_baseline` | `urllib.parse.urlsplit` + helpers — stdlib baseline |
| `urllib_urlparse_baseline` | `urllib.parse.urlparse` — compare with urlsplit |
| `parse_qsl_query_decoder` | `urllib.parse.parse_qsl` — repeated keys, blanks, plus signs, percent-encoding |
| `naive_split_scheme_host_path` | intentionally unsafe `split("://")` baseline — expected to fail |
| `naive_at_host_detector` | intentionally unsafe host extraction that gets userinfo wrong — expected to fail |
| `idna_codec_demo` | stdlib `.encode("idna")` for unicode hostnames — skip non-hosts |
| `ipaddress_host_check` | `ipaddress.ip_address` for IPv4/IPv6 literals — skip domain names |

**Categories covered:** normal, query, unicode, idna, path_normalization, userinfo, ipv6, port_error, non_http_scheme, ambiguous, malicious_looking

No compilers, no package managers, no Docker, no external corpora, no network calls during the benchmark. Python stdlib only.

## Running

```bash
python3 -m py_compile generate_cases.py run_lab.py
python3 generate_cases.py
python3 run_lab.py
```

Output:
- `cases/cases.jsonl` — 50 deterministic cases (seed 42)
- `results/results.jsonl` — per-method results
- `RESULTS.md` — summary table, skip matrix, failure list, conclusions

## Results (CPython 3.12.3)

| Method | Pass | Fail | Skip |
|---|---|---:|---:|
| urllib_urlsplit_baseline | 50 | 0 | 0 |
| urllib_urlparse_baseline | 50 | 0 | 0 |
| parse_qsl_query_decoder | 50 | 0 | 0 |
| naive_split_scheme_host_path | 46 | 4 | 0 |
| naive_at_host_detector | 40 | 10 | 0 |
| idna_codec_demo | 39 | 0 | 11 |
| ipaddress_host_check | 8 | 0 | 42 |

All naive failures are **expected** — that's the point.

See [RESULTS.md](RESULTS.md) for full details.

## Key findings

- `urllib.parse` does **NOT** normalize dot-segments (`/./`, `/../`) — documented, not WHATWG.
- `urllib.parse` does **NOT** perform IDNA/Punycode hostname normalization automatically — `.hostname` returns unicode as-is.
- Port parsing raises `ValueError` for out-of-range / non-numeric ports.
- Naive string splitting fails reliably on userinfo, query strings, fragments, IPv6 brackets, and malicious-looking URLs.
- `parse_qsl` correctly handles repeated keys, blank values, percent-encoding, and plus signs.
- For security-sensitive host allowlisting: **extract the hostname via a proper parser, never by naive splitting.**

## Scope

This lab is intentionally tiny. It does **not** claim urllib.parse is globally good or bad, and does **not** test WHATWG compliance. It tests the HN debate in a reproducible way: URLs are deceptively tricky, different parsers/specs disagree, naive splitting is dangerous, and even stdlib has stable behavior that may not match browsers.

No external parsers (can_ada, ada-python, yarl, hyperlink, requests, httpx, browsers, node, curl, jq) were used.

## Verify

See [VERIFY.md](VERIFY.md) for a fresh-clone verification transcript.
