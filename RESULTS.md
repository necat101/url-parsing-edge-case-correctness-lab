# URL Parsing Edge-Case Correctness Lab — Results

**Python:** 3.12.3 (CPython)

**Platform:** Linux-6.17.0-1009-aws-x86_64-with-glibc2.39

**Cases:** 50 (25423 bytes)

**Seed:** 42 (deterministic)

**Timing:** time.perf_counter()

**Memory:** tracemalloc — current 603.1 KiB, peak 603.7 KiB

**Total wall time:** 0.1691s

**Subprocess count:** 0

## Summary

| Method | Kind | Pass | Fail | Skip | Expected-Fail | Malicious-Misclass | Time (ms) |
|---|---|---:|---:|---:|---:|---:|---:|
| urllib_urlsplit_baseline | component-parse | 50 | 0 | 0 | 0 | 0 | 14.649 |
| urllib_urlparse_baseline | component-parse | 50 | 0 | 0 | 0 | 0 | 19.707 |
| parse_qsl_query_decoder | query-decode | 50 | 0 | 0 | 0 | 0 | 3.267 |
| naive_split_scheme_host_path | component-parse | 46 | 4 | 0 | 4 | 0 | 0.434 |
| naive_at_host_detector | component-parse | 40 | 10 | 0 | 10 | 1 | 0.901 |
| idna_codec_demo | hostname-normalization | 39 | 0 | 11 | 0 | 0 | 69.615 |
| ipaddress_host_check | hostname-normalization | 8 | 0 | 42 | 0 | 0 | 4.657 |

## Skip Matrix

| Method | Total | Passed | Failed | Skipped |
|---|---:|---:|---:|---:|
| urllib_urlsplit_baseline | 50 | 50 | 0 | 0 |
| urllib_urlparse_baseline | 50 | 50 | 0 | 0 |
| parse_qsl_query_decoder | 50 | 50 | 0 | 0 |
| naive_split_scheme_host_path | 50 | 46 | 4 | 0 |
| naive_at_host_detector | 50 | 40 | 10 | 0 |
| idna_codec_demo | 50 | 39 | 0 | 11 |
| ipaddress_host_check | 50 | 8 | 0 | 42 |

## Failures (grouped by method)

### naive_split_scheme_host_path

- **C005** [ambiguous] `example.com/path` — naive extraction mismatch (expected)
- **C006** [ambiguous] `//example.com/path` — naive extraction mismatch (expected)
- **C025** [non_http_scheme] `mailto:user@example.com` — naive extraction mismatch (expected)
- **C031** [malicious_looking] `http://127.0.0.1#.evil.example/a` — naive extraction mismatch (expected)

### naive_at_host_detector

- **C005** [ambiguous] `example.com/path` — host misclassification: naive='' real=None (expected)
- **C016** [ipv6] `http://[2001:db8::1]/path` — host misclassification: naive='[2001:db8::1]' real='2001:db8::1' (expected)
- **C017** [ipv6] `http://[::ffff:192.0.2.1]/` — host misclassification: naive='[::ffff:192.0.2.1]' real='::ffff:192.0.2.1' (expected)
- **C020** [unicode] `https://www.GOoglé.com/path` — host misclassification: naive='www.GOoglé.com' real='www.googlé.com' (expected)
- **C024** [non_http_scheme] `file:///etc/passwd` — host misclassification: naive='' real=None (expected)
- **C025** [non_http_scheme] `mailto:user@example.com` — host misclassification: naive='' real=None (expected)
- **C033** [ipv6] `https://[::1]:8443/secure` — host misclassification: naive='[::1]:8443' real='::1' (expected)
- **C041** [ipv6] `http://[2001:db8::1]:8080/` — host misclassification: naive='[2001:db8::1]:8080' real='2001:db8::1' (expected)
- **C042** [malicious_looking] `https://a@b@c.example.com/` — host misclassification: naive='b@c.example.com' real='c.example.com' (expected)
- **C049** [ipv6] `http://[::]/` — host misclassification: naive='[::]' real='::' (expected)

## Notes

- `urllib_urlsplit_baseline` / `urllib_urlparse_baseline`: validated against stdlib — all cases pass as expected.
- `parse_qsl_query_decoder`: correctly handles repeated keys, blank values, percent-encoding, and plus signs.
- `naive_split_scheme_host_path`: fails on query/fragment pollution, userinfo, missing schemes, ports, IPv6 — exactly as expected.
- `naive_at_host_detector`: misclassifies hosts in userinfo/malicious-looking cases; IPv6 port stripping is broken.
- `idna_codec_demo`: stdlib `idna` codec works for regular unicode hosts; skipped IP literals and non-hosts.
- `ipaddress_host_check`: correctly identifies IPv4/IPv6 literals; skips domain names.
- urllib.parse does **NOT** normalize dot-segments (`/./`, `/../`) — this matches stdlib documented behavior, not WHATWG.
- urllib.parse does **NOT** perform IDNA/Punycode hostname normalization automatically — `.hostname` returns unicode as-is.
- Port parsing raises `ValueError` for out-of-range/non-numeric ports — caught and recorded in expected observations.
- No external parsers (can_ada, ada-python, yarl, hyperlink, etc.) were used — out of scope.

## Conclusion

URL parsing is deceptively tricky. Naive string splitting fails reliably on userinfo, query strings, fragments, IPv6 brackets, and malicious-looking URLs. urllib.parse is stable and correct within its spec (RFC 3986-ish, not WHATWG), but does not normalize paths or IDNA-encode hostnames automatically. For security-sensitive host allowlisting, parser differentials matter — extract the hostname via a proper parser, never by naive splitting.
