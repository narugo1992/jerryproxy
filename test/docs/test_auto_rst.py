from pathlib import Path

import pytest

from auto_rst import convert_code_to_rst, extract_public_members
from auto_rst_top_index import generate_rst_index


@pytest.mark.unittest
def test_extract_public_members_ignores_private_names():
    members = extract_public_members(
        "VALUE = 1\n"
        "_PRIVATE = 2\n"
        "class Public:\n"
        "    field = 3\n"
        "    def run(self):\n"
        "        return None\n"
        "    def _hidden(self):\n"
        "        return None\n"
        "def execute():\n"
        "    return None\n"
        "def _helper():\n"
        "    return None\n"
    )

    assert members == {
        "variables": ["VALUE"],
        "classes": [("Public", ["field", "run"])],
        "functions": ["execute"],
    }


@pytest.mark.unittest
def test_convert_package_initializer_adds_public_children(tmp_path):
    source_root = tmp_path
    parent = source_root / "example"
    parent.mkdir()
    (parent / "__init__.py").write_text("", encoding="utf-8")
    package = parent / "child"
    package.mkdir(parents=True)
    initializer = package / "__init__.py"
    initializer.write_text('"""Example package."""\n', encoding="utf-8")
    (package / "module.py").write_text("def run():\n    return None\n", encoding="utf-8")
    (package / "_private.py").write_text("", encoding="utf-8")
    child = package / "child"
    child.mkdir()
    (child / "__init__.py").write_text("", encoding="utf-8")
    output = tmp_path / "index.rst"

    convert_code_to_rst(initializer, output, source_root)

    generated = output.read_text(encoding="utf-8")
    assert "example.child\n" in generated
    assert "   module\n" in generated
    assert "   child/index\n" in generated
    assert "_private" not in generated


@pytest.mark.unittest
def test_top_index_is_english_and_excludes_private_modules(tmp_path):
    package = tmp_path / "jerryproxy"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "home.py").write_text("", encoding="utf-8")
    (package / "_private.py").write_text("", encoding="utf-8")
    backend = package / "backend"
    backend.mkdir()
    (backend / "__init__.py").write_text("", encoding="utf-8")
    output = tmp_path / "api_doc.rst"

    generate_rst_index(package, output)

    generated = Path(output).read_text(encoding="utf-8")
    assert "API Reference" in generated
    assert "api_doc/home" in generated
    assert "api_doc/backend/index" in generated
    assert "_private" not in generated
    assert all(ord(character) < 128 for character in generated)


@pytest.mark.unittest
def test_generated_data_directives_hide_runtime_values(tmp_path):
    source = tmp_path / "example.py"
    source.write_text("SETTINGS = {'secret': object()}\n", encoding="utf-8")
    output = tmp_path / "example.rst"

    convert_code_to_rst(source, output, tmp_path)

    generated = output.read_text(encoding="utf-8")
    assert ".. autodata:: SETTINGS\n   :no-value:" in generated
