import ast
from pathlib import Path


def test_every_test_directory_is_a_python_package():
    test_root = Path(__file__).parent
    test_directories = (
        path
        for path in test_root.rglob("*")
        if path.is_dir() and path.name != "__pycache__"
    )

    missing_initializers = [
        str(path.relative_to(test_root))
        for path in test_directories
        if not (path / "__init__.py").is_file()
    ]

    assert not missing_initializers, (
        "Every directory in test/ must be a Python package; missing __init__.py: "
        + ", ".join(sorted(missing_initializers))
    )


def test_backend_catalog_resource_reads_stay_inside_the_data_module():
    project_root = Path(__file__).parent.parent
    catalog_source = project_root / "jerryproxy" / "backend" / "catalog.py"
    assert "from jerryproxy.data import" in catalog_source.read_text(encoding="utf-8")
    allowed = {
        project_root / "jerryproxy" / "data" / "__init__.py",
        project_root / "jerryproxy" / "selfcheck.py",
    }
    violations = []
    for source in (project_root / "jerryproxy").rglob("*.py"):
        if source in allowed:
            continue
        text = source.read_text(encoding="utf-8")
        forbidden = (
            "pkgutil.get_data",
            "importlib.resources",
            "mihomo.json",
            "sing-box.json",
            "v2ray.json",
            "xray.json",
        )
        if any(marker in text for marker in forbidden):
            violations.append(str(source.relative_to(project_root)))
    assert not violations, "catalog resources must be read through jerryproxy.data: %s" % ", ".join(violations)


def test_product_tests_do_not_import_repository_tools():
    test_root = Path(__file__).parent
    violations = []
    for source in test_root.rglob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.split(".", 1)[0] == "tools":
                violations.append(str(source.relative_to(test_root)))
            if isinstance(node, ast.Import) and any(alias.name.split(".", 1)[0] == "tools" for alias in node.names):
                violations.append(str(source.relative_to(test_root)))
    assert not violations, "test/ must only exercise the jerryproxy product: %s" % ", ".join(violations)
