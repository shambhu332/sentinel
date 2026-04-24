"""Unit tests for S_001 scope parser.

Uses offline HTML fixtures so tests run without internet.
"""
import json
from pathlib import Path

import httpx
import pytest

from sentinel.scope.scope_parser import ScopeParser, ScopeSourceError, parse_scope

# ---------- Fixtures ----------

HACKERONE_HTML = """
<html><head><title>Shopify Program | HackerOne</title></head>
<body>
<h2>In Scope</h2>
<ul>
  <li>com.shopify.mobile (Android)</li>
  <li>com.shopify.pos (Android)</li>
  <li>shopify.com</li>
  <li>*.myshopify.com</li>
</ul>
<h2>Out of Scope</h2>
<ul>
  <li>com.shopify.legacy.test</li>
  <li>status.shopify.com</li>
</ul>
<h2>Rewards</h2>
<p>Critical: $5,000 - $50,000</p>
<p>High: $1,000 - $5,000</p>
<p>Medium: $500 - $1,000</p>
<p>Low: $100 - $500</p>
<h2>Rules</h2>
<p>Denial of service attacks are not permitted.</p>
<p>Social engineering of employees is strictly forbidden.</p>
</body></html>
"""

BUGCROWD_HTML = """
<html><head><title>Acme Corp · Bugcrowd</title></head>
<body>
<section>
<h3>Targets</h3>
<p>com.acme.banking</p>
<p>api.acme.com</p>
</section>
<section>
<h3>Exclusions</h3>
<p>com.acme.internal.debug</p>
<p>No brute force attacks.</p>
<p>DDoS prohibited.</p>
</section>
<p>Critical $2,000 to $20,000</p>
</body></html>
"""

YESWEHACK_HTML = """
<html><head><title>SecureApp - YesWeHack</title></head>
<body>
<div>In Scope: com.secureapp.android, secureapp.com</div>
<div>Out of Scope: com.secureapp.staging</div>
<div>Critical: $1,500 - $10,000</div>
</body></html>
"""


# ---------- Mock HTTP transport ----------

class FixtureTransport(httpx.BaseTransport):
    def __init__(self, body: str, status: int = 200):
        self.body = body
        self.status = status

    def handle_request(self, request):
        return httpx.Response(
            status_code=self.status,
            content=self.body.encode(),
            request=request,
            headers={"content-type": "text/html; charset=utf-8"},
        )


class FailingTransport(httpx.BaseTransport):
    def handle_request(self, request):
        raise httpx.ConnectError("mock connection refused")


def _parser_with_fixture(html: str, status: int = 200) -> ScopeParser:
    parser = ScopeParser()
    # Monkey-patch _fetch to use fixture
    def _mock_fetch(url: str) -> str:
        if status != 200:
            raise httpx.HTTPError(f"mock {status}")
        return html
    parser._fetch = _mock_fetch  # type: ignore
    return parser


# ---------- Platform detection ----------

def test_detect_hackerone():
    assert ScopeParser()._detect_platform("https://hackerone.com/shopify") == "hackerone"

def test_detect_bugcrowd():
    assert ScopeParser()._detect_platform("https://bugcrowd.com/acme") == "bugcrowd"

def test_detect_yeswehack():
    assert ScopeParser()._detect_platform("https://yeswehack.com/programs/app") == "yeswehack"

def test_detect_intigriti():
    assert ScopeParser()._detect_platform("https://app.intigriti.com/programs/x") == "intigriti"

def test_detect_immunefi():
    assert ScopeParser()._detect_platform("https://immunefi.com/bug-bounty/project") == "immunefi"

def test_detect_unknown():
    assert ScopeParser()._detect_platform("https://example.com/scope") == "unknown"


# ---------- URL safety ----------

def test_rejects_localhost():
    with pytest.raises(ScopeSourceError):
        ScopeParser().from_url("http://localhost/scope")

def test_rejects_private_ip():
    with pytest.raises(ScopeSourceError):
        ScopeParser().from_url("http://192.168.1.1/scope")

def test_rejects_non_http():
    with pytest.raises(ScopeSourceError):
        ScopeParser().from_url("file:///etc/passwd")

def test_rejects_ftp():
    with pytest.raises(ScopeSourceError):
        ScopeParser().from_url("ftp://example.com/scope")


# ---------- HackerOne parsing ----------

def test_hackerone_full_parse():
    parser = _parser_with_fixture(HACKERONE_HTML)
    scope = parser.from_url("https://hackerone.com/shopify")

    assert scope.platform == "hackerone"
    assert "com.shopify.mobile" in scope.in_scope_packages
    assert "com.shopify.pos" in scope.in_scope_packages
    assert "com.shopify.legacy.test" in scope.out_of_scope_packages
    assert "Shopify Program" in scope.program_name
    assert "dos" in scope.forbidden_techniques
    assert "social-engineering" in scope.forbidden_techniques
    assert scope.reward_ranges.get("critical") == (5000, 50000)
    assert scope.reward_ranges.get("high") == (1000, 5000)


# ---------- Bugcrowd parsing ----------

def test_bugcrowd_parse():
    parser = _parser_with_fixture(BUGCROWD_HTML)
    scope = parser.from_url("https://bugcrowd.com/acme")

    assert scope.platform == "bugcrowd"
    assert "com.acme.banking" in scope.in_scope_packages
    assert "com.acme.internal.debug" in scope.out_of_scope_packages
    assert "brute-force" in scope.forbidden_techniques
    assert "dos" in scope.forbidden_techniques


# ---------- YesWeHack parsing ----------

def test_yeswehack_parse():
    parser = _parser_with_fixture(YESWEHACK_HTML)
    scope = parser.from_url("https://yeswehack.com/programs/secureapp")

    assert scope.platform == "yeswehack"
    assert "com.secureapp.android" in scope.in_scope_packages
    assert "com.secureapp.staging" in scope.out_of_scope_packages


# ---------- Fetch failure ----------

def test_url_fetch_failure_raises():
    parser = ScopeParser()
    parser._fetch = lambda url: (_ for _ in ()).throw(httpx.ConnectError("no net"))
    with pytest.raises(ScopeSourceError):
        parser.from_url("https://hackerone.com/test")


# ---------- File input ----------

def test_from_file_json(tmp_path):
    data = {
        "program_name": "Test Program",
        "platform": "hackerone",
        "in_scope_packages": ["com.test.app"],
        "out_of_scope_packages": ["com.test.debug"],
        "forbidden_techniques": ["dos", "social-engineering"],
        "reward_ranges": {"critical": [1000, 10000]},
    }
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(data))

    scope = ScopeParser().from_file(p)
    assert scope.program_name == "Test Program"
    assert "com.test.app" in scope.in_scope_packages
    assert "dos" in scope.forbidden_techniques
    assert scope.reward_ranges["critical"] == (1000, 10000)


def test_from_file_text_plain(tmp_path):
    p = tmp_path / "scope.txt"
    p.write_text("In Scope\ncom.myapp.android\nOut of Scope\ncom.myapp.test")
    scope = ScopeParser().from_file(p)
    assert "com.myapp.android" in scope.in_scope_packages


def test_from_file_missing(tmp_path):
    with pytest.raises(ScopeSourceError, match="not found"):
        ScopeParser().from_file(tmp_path / "nope.json")


def test_from_file_too_large(tmp_path):
    p = tmp_path / "huge.txt"
    p.write_text("x" * 600_000)
    with pytest.raises(ScopeSourceError, match="too large"):
        ScopeParser().from_file(p)


# ---------- Text input ----------

def test_from_text_basic():
    text = "In scope: com.myapp.android, com.myapp.ios. Out of scope: com.myapp.test"
    scope = ScopeParser().from_text(text)
    assert "com.myapp.android" in scope.in_scope_packages


def test_from_text_too_large():
    with pytest.raises(ScopeSourceError, match="too large"):
        ScopeParser().from_text("x" * 600_000)


# ---------- parse_scope convenience function ----------

def test_parse_scope_file_fallback_when_no_url(tmp_path):
    p = tmp_path / "scope.json"
    p.write_text(json.dumps({"in_scope_packages": ["com.fallback.app"]}))
    scope = parse_scope(file=p)
    assert "com.fallback.app" in scope.in_scope_packages


def test_parse_scope_text_when_nothing_else():
    scope = parse_scope(text="In scope: com.direct.app")
    assert "com.direct.app" in scope.in_scope_packages


def test_parse_scope_no_sources():
    with pytest.raises(ScopeSourceError, match="No scope source"):
        parse_scope()


# ---------- BountyScope integration ----------

def test_parsed_scope_gates_packages():
    parser = _parser_with_fixture(HACKERONE_HTML)
    scope = parser.from_url("https://hackerone.com/shopify")
    assert scope.package_in_scope("com.shopify.mobile")
    assert not scope.package_in_scope("com.shopify.legacy.test")
    assert not scope.package_in_scope("com.random.other")


def test_parsed_scope_blocks_forbidden_techniques():
    parser = _parser_with_fixture(HACKERONE_HTML)
    scope = parser.from_url("https://hackerone.com/shopify")
    assert not scope.technique_allowed("dos")
    assert scope.technique_allowed("static-analysis")
