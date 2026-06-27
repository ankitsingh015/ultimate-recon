import sys
import json
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from src.analyzer import ReconAnalyzer


def test_analyzer_initializes():
    with tempfile.TemporaryDirectory() as td:
        a = ReconAnalyzer(td, "example.com")
        assert a.target == "example.com"
        assert a.analysis_dir.exists()


def test_categorize_admin():
    with tempfile.TemporaryDirectory() as td:
        a = ReconAnalyzer(td, "example.com")
        assert a._categorize_subdomain("admin.example.com") == "admin"
        assert a._categorize_subdomain("dashboard.example.com") == "admin"


def test_categorize_dev():
    with tempfile.TemporaryDirectory() as td:
        a = ReconAnalyzer(td, "example.com")
        assert a._categorize_subdomain("staging.example.com") == "dev"
        assert a._categorize_subdomain("test.example.com") == "dev"


def test_categorize_api():
    with tempfile.TemporaryDirectory() as td:
        a = ReconAnalyzer(td, "example.com")
        assert a._categorize_subdomain("api.example.com") == "api"
        assert a._categorize_subdomain("graphql.example.com") == "api"


def test_categorize_returns_none():
    with tempfile.TemporaryDirectory() as td:
        a = ReconAnalyzer(td, "example.com")
        assert a._categorize_subdomain("www.example.com") is None


def test_interesting_url():
    with tempfile.TemporaryDirectory() as td:
        a = ReconAnalyzer(td, "example.com")
        assert a._interesting_url("https://example.com/login.php") == "login"
        assert a._interesting_url("https://example.com/upload") == "upload"
        assert a._interesting_url("https://example.com/api/v1/users") == "api"


def test_sensitive_extension():
    with tempfile.TemporaryDirectory() as td:
        a = ReconAnalyzer(td, "example.com")
        assert a._sensitive_extension("https://example.com/db.sql") == ".sql"
        assert a._sensitive_extension("https://example.com/.env") == ".env"
        assert a._sensitive_extension("https://example.com/index.html") is None


def test_tech_alerts_apache():
    with tempfile.TemporaryDirectory() as td:
        a = ReconAnalyzer(td, "example.com")
        alerts = a._tech_alerts("Apache httpd", "2.4.49")
        assert len(alerts) > 0
        assert "CVE-2021-41773" in alerts[0]


def test_tech_alerts_wordpress():
    with tempfile.TemporaryDirectory() as td:
        a = ReconAnalyzer(td, "example.com")
        alerts = a._tech_alerts("WordPress", "6.0")
        assert len(alerts) > 0
        assert "WPScan" in alerts[0]


def test_phase1_analysis_structure():
    with tempfile.TemporaryDirectory() as td:
        a = ReconAnalyzer(td, "example.com")
        result = a._analyze_phase1({"subdomains": ["admin.example.com", "www.example.com"], "ips": [], "tech_stack": {}})
        assert "interesting_hosts" in result
        assert "recommendations" in result
        assert result["phase"] == 1
        assert "admin" in result["interesting_hosts"]


def test_phase2_analysis_structure():
    with tempfile.TemporaryDirectory() as td:
        a = ReconAnalyzer(td, "example.com")
        result = a._analyze_phase2({"urls": ["https://example.com/login"], "live_hosts": ["https://example.com"], "tech_stack": {}})
        assert "interesting_urls" in result
        assert "recommendations" in result
        assert "sensitive_files" in result


def test_phase3_analysis_structure():
    with tempfile.TemporaryDirectory() as td:
        a = ReconAnalyzer(td, "example.com")
        result = a._analyze_phase3({"params": {"sqli": ["https://example.com?id=1"]}, "ports": [], "js_secrets": []})
        assert "param_opportunities" in result
        assert "recommendations" in result


def test_phase4_analysis_structure():
    with tempfile.TemporaryDirectory() as td:
        a = ReconAnalyzer(td, "example.com")
        result = a._analyze_phase4({"vulnerabilities": [{"type": "xss", "severity": "high", "url": "https://example.com"}]})
        assert "confirmed_vulns" in result
        assert "recommendations" in result


def test_chain_vulnerabilities_xss_cors():
    with tempfile.TemporaryDirectory() as td:
        a = ReconAnalyzer(td, "example.com")
        chains = a.chain_vulnerabilities(
            [{"type": "xss", "severity": "high"}, {"type": "cors", "severity": "medium"}],
            {}
        )
        assert len(chains) > 0
        assert "XSS" in chains[0]["name"]


def test_save_analysis_creates_files():
    with tempfile.TemporaryDirectory() as td:
        a = ReconAnalyzer(td, "example.com")
        a.save_analysis("phase1", {"phase": 1, "recommendations": ["Test rec"]})
        assert (a.analysis_dir / "phase1-analysis.json").exists()
        assert (a.analysis_dir / "phase1-summary.txt").exists()


def test_finalize_creates_output():
    with tempfile.TemporaryDirectory() as td:
        a = ReconAnalyzer(td, "example.com")
        a.finalize()
        assert (a.analysis_dir / "full-analysis.json").exists()
        assert (a.analysis_dir / "highlights.txt").exists()
