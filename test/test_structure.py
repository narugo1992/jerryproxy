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
