import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from src.tool_registry import ToolRegistry


def test_all_tools_registered():
    assert len(ToolRegistry.TOOLS) > 50, f"Expected 50+ tools, got {len(ToolRegistry.TOOLS)}"


def test_tool_has_required_fields():
    required = {"name", "category", "description", "cmd_template", "output_ext", "phase"}
    for t in ToolRegistry.TOOLS.values():
        for field in required:
            assert field in t, f"Tool '{t['name']}' missing field '{field}'"


def test_get_returns_none_for_unknown():
    assert ToolRegistry.get("nonexistent_tool_xyz") is None


def test_get_returns_tool():
    t = ToolRegistry.get("subfinder")
    assert t is not None
    assert t["name"] == "subfinder"


def test_list_by_category():
    subdomain_tools = ToolRegistry.list_by_category("subdomain")
    assert len(subdomain_tools) >= 10


def test_categories_returns_all():
    cats = ToolRegistry.categories()
    assert "subdomain" in cats
    assert "vuln" in cats
    assert "port" in cats
    assert "dir" in cats


def test_build_cmd_replaces_target():
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "out.txt"
        cmd = ToolRegistry.build_cmd("subfinder", "example.com", out)
        assert cmd is not None
        assert "example.com" in cmd
        assert str(out) in cmd


def test_build_cmd_replaces_api_key():
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "out.txt"
        cmd = ToolRegistry.build_cmd("virustotal", "example.com", out, {"virustotal": "mykey123"})
        assert cmd is not None
        assert "mykey123" in cmd


def test_build_cmd_returns_none_for_unknown():
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "out.txt"
        cmd = ToolRegistry.build_cmd("does_not_exist", "example.com", out)
        assert cmd is None


def test_tool_phases_are_1_to_5():
    for t in ToolRegistry.TOOLS.values():
        assert 1 <= t["phase"] <= 5, f"Tool '{t['name']}' has invalid phase {t['phase']}"


def test_no_missing_needs_api_keys():
    api_tools = [t for t in ToolRegistry.TOOLS.values() if t.get("needs_api")]
    known_services = {"virustotal", "github", "shodan", "chaos", "securitytrails", "chaos"}
    for t in api_tools:
        assert t["needs_api"] in known_services, f"Unknown API service '{t['needs_api']}' for tool '{t['name']}'"
