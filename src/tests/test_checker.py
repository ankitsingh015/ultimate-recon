import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from src.checker import ToolChecker, DependencyChecker


def test_checker_initializes():
    c = ToolChecker()
    assert c.results["available"] == []
    assert c.results["missing"] == []


def test_check_tool_returns_bool():
    c = ToolChecker()
    assert isinstance(c.check_tool("python3"), bool)


def test_check_tool_known_tool():
    c = ToolChecker()
    result = c.check_tool("sh")
    assert isinstance(result, bool)


def test_check_all_returns_dict():
    c = ToolChecker()
    results = c.check_all()
    assert "available" in results
    assert "missing" in results
    assert "total" in results
    assert "available_count" in results
    assert "missing_count" in results
    assert results["total"] > 0


def test_check_python_version():
    assert DependencyChecker.check_python_version()


def test_check_disk_space():
    free_gb, ok = DependencyChecker.check_disk_space()
    assert isinstance(free_gb, (int, float))
    assert isinstance(ok, bool)


def test_check_network_is_bool():
    result = DependencyChecker.check_network()
    assert isinstance(result, bool)


def test_summary_format():
    c = ToolChecker()
    c.check_all()
    s = c.summary()
    assert "Tools:" in s
    assert "/" in s
    assert "%" in s


def test_check_api_keys_no_config():
    with tempfile.TemporaryDirectory() as td:
        c = ToolChecker(config_dir=td)
        result = c.check_api_keys()
        assert result["status"] == "no_config"


def test_python_tools_list_not_empty():
    assert len(ToolChecker.PYTHON_TOOLS) > 0
