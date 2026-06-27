import sys
import json
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from src.ai_engine import OpenCodeProvider, AIEngine


def test_opencode_provider_name():
    p = OpenCodeProvider()
    assert p.name() == "opencode"


def test_rule_based_fallback_returns_dict():
    p = OpenCodeProvider()
    result = p._rule_based_fallback({
        "subdomains": ["admin.example.com", "api.example.com"],
        "urls": [],
        "tech_stack": {},
        "vulnerabilities": []
    })
    assert "interesting_hosts" in result
    assert "recommendations" in result
    assert "admin" in result["interesting_hosts"]
    assert "api" in result["interesting_hosts"]


def test_rule_based_fallback_empty():
    p = OpenCodeProvider()
    result = p._rule_based_fallback({
        "subdomains": [],
        "urls": [],
        "tech_stack": {},
        "vulnerabilities": []
    })
    assert result["interesting_hosts"] == {}


def test_rule_based_fallback_tech_alerts():
    p = OpenCodeProvider()
    result = p._rule_based_fallback({
        "subdomains": [],
        "urls": [],
        "tech_stack": {"Apache httpd": "2.4.49"},
        "vulnerabilities": []
    })
    assert len(result.get("tech_alerts", [])) > 0


def test_rule_based_fallback_wordpress_detection():
    p = OpenCodeProvider()
    result = p._rule_based_fallback({
        "subdomains": [],
        "urls": [],
        "tech_stack": {"WordPress": "6.0"},
        "vulnerabilities": []
    })
    recs = " ".join(result.get("recommendations", []))
    assert "WPScan" in recs or "WordPress" in recs


def test_ai_engine_initializes():
    with tempfile.TemporaryDirectory() as td:
        config_dir = Path(td)
        workspace = Path(td) / "ws"
        workspace.mkdir()
        engine = AIEngine(config_dir, workspace)
        assert engine.provider is not None


def test_ai_engine_creates_opencode_by_default():
    with tempfile.TemporaryDirectory() as td:
        config_dir = Path(td)
        workspace = Path(td) / "ws"
        workspace.mkdir()
        engine = AIEngine(config_dir, workspace)
        assert engine.provider.name() == "opencode"
