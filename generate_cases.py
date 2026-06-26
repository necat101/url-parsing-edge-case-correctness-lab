#!/usr/bin/env python3
"""
generate_cases.py — deterministic URL parsing edge-case corpus.

Uses Python stdlib (urllib.parse, ipaddress, json, pathlib) as the source of truth.
Seed: 42
"""
import json
import ipaddress
from pathlib import Path
import urllib.parse

SEED = 42
OUT_DIR = Path("cases")
OUT_FILE = OUT_DIR / "cases.jsonl"

RAW_CASES = [
    # id, url, category, notes
    ("C001", "https://example.com/path", "normal", ""),
    ("C002", "http://example.com:8080/docs", "normal", ""),
    ("C003", "https://example.com/a/./b/../c", "path_normalization", "urllib does NOT normalize dot-segments"),
    ("C004", "https://example.com//double//slash", "path_normalization", "repeated slashes preserved"),
    ("C005", "example.com/path", "ambiguous", "no scheme"),
    ("C006", "//example.com/path", "ambiguous", "scheme-relative"),
    ("C007", "https://example.com/search?q=foo&q=bar&a=1", "query", "repeated keys"),
    ("C008", "https://example.com/?a=&b", "query", "blank values"),
    ("C009", "https://example.com/path%20with%20spaces", "query", "percent-encoded spaces"),
    ("C010", "https://example.com/path?q=a%2Fb", "query", "percent-encoded slash in query"),
    ("C011", "https://example.com/?x=a+b", "query", "plus sign in query"),
    ("C012", "https://example.com/page#section", "normal", "fragment"),
    ("C013", "https://user:pass@example.com/secret", "userinfo", ""),
    ("C014", "https://user@example.com/", "userinfo", "username only"),
    ("C015", "http://192.168.1.1/admin", "ipv4", ""),
    ("C016", "http://[2001:db8::1]/path", "ipv6", ""),
    ("C017", "http://[::ffff:192.0.2.1]/", "ipv6", ""),
    ("C018", "http://example.com:99999/path", "port_error", "out of range port"),
    ("C019", "http://example.com:abc/path", "port_error", "non-numeric port"),
    ("C020", "https://www.GOoglé.com/path", "unicode", "unicode hostname"),
    ("C021", "https://www.xn--googl-fsa.com/path", "idna", "punycode hostname"),
    ("C022", "https://example.com/café", "unicode", "unicode path"),
    ("C023", "https://www.googl\u2011e.com/path", "unicode", "non-breaking hyphen lookalike"),
    ("C024", "file:///etc/passwd", "non_http_scheme", ""),
    ("C025", "mailto:user@example.com", "non_http_scheme", ""),
    ("C026", "https://example.com", "normal", "empty path"),
    ("C027", "https://example.com/", "normal", "slash path"),
    ("C028", "https://example.com/path;params", "normal", "semicolon path params"),
    ("C029", "https://example.com/path?a=1;2", "query", "semicolon in query"),
    ("C030", "https://trusted.example.com@evil.example.net/path", "malicious_looking", "userinfo host confusion"),
    ("C031", "http://127.0.0.1#.evil.example/a", "malicious_looking", "fragment trick"),
    ("C032", "http://user:pw@192.168.0.1:8080/x", "userinfo", "userinfo + ipv4 + port"),
    ("C033", "https://[::1]:8443/secure", "ipv6", "ipv6 with port"),
    ("C034", "https://example.com?a=1&a=2&a=3", "query", "triple repeated key"),
    ("C035", "https://example.com/?q=%20+%2B", "query", "mixed encodings"),
    ("C036", "https://example.com/path#frag?weird", "normal", "fragment with question mark"),
    ("C037", "https://例え.jp/テスト", "unicode", "fully unicode URL"),
    ("C038", "http://example.com:0/", "port_error", "port zero"),
    ("C039", "ftp://ftp.example.com/file.txt", "non_http_scheme", ""),
    ("C040", "https://example.com/path?q=hello%20world&lang=en", "query", "percent space + normal param"),
    ("C041", "http://[2001:db8::1]:8080/", "ipv6", "ipv6 bracket + port"),
    ("C042", "https://a@b@c.example.com/", "malicious_looking", "multiple @ signs"),
    ("C043", "https://example.com:443/path", "normal", "explicit default https port"),
    ("C044", "http://user%40name:pass@example.com/", "userinfo", "percent-encoded @ in username"),
    ("C045", "https://example.com/path%2Fsegment", "query", "percent-encoded path slash"),
    ("C046", "https://xn--fsq.jp/", "idna", "punycode jp"),
    ("C047", "https://example.com/?", "query", "empty query string"),
    ("C048", "https://example.com/#", "normal", "empty fragment"),
    ("C049", "http://[::]/", "ipv6", "ipv6 unspecified"),
    ("C050", "https://example.com/path?q=%E2%98%83", "query", "percent-encoded unicode snowman"),
]

def build_expected(url: str, category: str):
    """Build expected observations using urllib.parse as baseline truth."""
    try:
        split = urllib.parse.urlsplit(url)
        parsed = urllib.parse.urlparse(url)
    except Exception as e:
        return {"parse_error": str(e)}

    # Query pairs via parse_qsl
    try:
        q_pairs = urllib.parse.parse_qsl(split.query, keep_blank_values=True)
    except Exception:
        q_pairs = []

    # Hostname / port via urlsplit — port can raise ValueError
    def safe_getattr(obj, name):
        try:
            return getattr(obj, name)
        except ValueError as e:
            return f"<ValueError: {e}>"
        except Exception:
            return None
    hostname = safe_getattr(split, "hostname")
    port = safe_getattr(split, "port")
    username = safe_getattr(split, "username")
    password = safe_getattr(split, "password")

    # IP check
    ip_kind = None
    if hostname:
        try:
            ip = ipaddress.ip_address(hostname.strip("[]"))
            ip_kind = f"ipv{ip.version}"
        except Exception:
            pass

    # IDNA check
    idna_encoded = None
    idna_applicable = False
    if hostname and not ip_kind:
        try:
            idna_encoded = hostname.encode("idna").decode("ascii")
            idna_applicable = True
        except Exception:
            pass

    # dot-segment normalization caveat
    dot_segments = "/./" in split.path or "/../" in split.path

    return {
        "scheme": split.scheme,
        "netloc": split.netloc,
        "hostname": hostname,
        "port": port,
        "path": split.path,
        "query": split.query,
        "query_pairs": q_pairs,
        "fragment": split.fragment,
        "username": username,
        "password": password,
        "urlparse_path": parsed.path,
        "urlparse_params": parsed.params,
        "ip_kind": ip_kind,
        "idna_encoded": idna_encoded,
        "idna_applicable": idna_applicable,
        "dot_segments_present": dot_segments,
        "dot_segments_normalized": False,  # urllib does NOT normalize
    }


def main():
    OUT_DIR.mkdir(exist_ok=True)
    seen = set()
    with OUT_FILE.open("w", encoding="utf-8") as f:
        for case_id, url, category, notes in RAW_CASES:
            if case_id in seen:
                raise ValueError(f"duplicate {case_id}")
            seen.add(case_id)
            expected = build_expected(url, category)
            rec = {
                "case_id": case_id,
                "url": url,
                "category": category,
                "notes": notes,
                "expected": expected,
            }
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"Wrote {len(RAW_CASES)} cases to {OUT_FILE} ({OUT_FILE.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
