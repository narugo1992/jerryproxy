"""Generate deterministic Sphinx API pages from Python source files."""

import argparse
import ast
import os
import re
from io import StringIO
from pathlib import Path

_RST_SYMBOLS_RE = re.compile(r"([!-\-/:-@\[-`{-~])")
_MEMBER_TITLE_MIN_WIDTH = 53


def _escape_rst(text):
    try:
        from sphinx.util.rst import escape
    except ModuleNotFoundError as error:
        # Sphinx is optional when the generator is exercised by unit tests.
        if error.name != "sphinx":
            raise
        escaped = _RST_SYMBOLS_RE.sub(r"\\\1", text)
        return re.sub(r"^\.", r"\.", escaped)
    return escape(text)


def _natural_key(value):
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", value)]


def _is_magic(name):
    return name.startswith("__") and name.endswith("__") and len(name) > 4


def _is_public(name):
    return not name.startswith("_") or _is_magic(name)


def _assignment_names(node):
    names = []
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    for target in targets:
        if isinstance(target, ast.Name) and _is_public(target.id):
            names.append(target.id)
    return names


def _function_name(node):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _is_public(node.name):
        return node.name
    return None


def extract_public_members(source_code):
    """Return public module variables, classes, functions, and class members."""
    tree = ast.parse(source_code)
    variables = []
    classes = []
    functions = []

    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            variables.extend(_assignment_names(node))
            continue

        if isinstance(node, ast.ClassDef) and _is_public(node.name):
            class_members = []
            for item in node.body:
                member_name = _function_name(item)
                if member_name is not None:
                    class_members.append(member_name)
                elif isinstance(item, (ast.Assign, ast.AnnAssign)):
                    class_members.extend(_assignment_names(item))
            classes.append((node.name, class_members))
            continue

        function_name = _function_name(node)
        if function_name is not None:
            functions.append(function_name)

    return {
        "variables": variables,
        "classes": classes,
        "functions": functions,
    }


def normalize_rst_document(text):
    """Return a non-empty document with exactly one trailing newline."""
    stripped = text.rstrip()
    return "%s\n" % stripped if stripped else ""


def _write_text_lf(path, text):
    with Path(path).open("w", encoding="utf-8", newline="\n") as output:
        output.write(text)


def _print_member_title(output, name):
    title = _escape_rst(name)
    print(title, file=output)
    print("-" * max(_MEMBER_TITLE_MIN_WIDTH, len(title)), file=output)
    print("", file=output)


def _print_members(output, members):
    for name in members["variables"]:
        _print_member_title(output, name)
        print(".. autodata:: %s" % name, file=output)
        print("   :no-value:", file=output)
        print("", file=output)
        print("", file=output)

    for name, class_members in members["classes"]:
        _print_member_title(output, name)
        print(".. autoclass:: %s" % name, file=output)
        if class_members:
            print("   :members: %s" % ",".join(class_members), file=output)
        print("", file=output)
        print("", file=output)

    for name in members["functions"]:
        _print_member_title(output, name)
        print(".. autofunction:: %s" % name, file=output)
        print("", file=output)
        print("", file=output)


def _package_children(code_file):
    children = []
    for child in Path(code_file).parent.iterdir():
        if child.is_file() and child.suffix == ".py":
            if child.stem.startswith("_") or child.name == "__init__.py":
                continue
            children.append(child.stem)
        elif child.is_dir() and (child / "__init__.py").is_file():
            if child.name.startswith("_"):
                continue
            children.append("%s/index" % child.name)
    return sorted(children, key=_natural_key)


def _print_package_toctree(output, code_file):
    children = _package_children(code_file)
    if not children:
        return
    print(".. toctree::", file=output)
    print("   :maxdepth: 3", file=output)
    print("", file=output)
    for child in children:
        print("   %s" % child, file=output)
    print("", file=output)


def _module_name(code_file, source_root):
    relative = os.path.relpath(os.path.abspath(code_file), os.path.abspath(source_root))
    module = os.path.splitext(relative)[0].replace("/", ".").replace("\\", ".")
    if module.split(".")[-1] == "__init__":
        module = ".".join(module.split(".")[:-1])
    return module


def convert_code_to_rst(code_file, rst_file, source_root="."):
    """Generate one RST API page for a Python module or package initializer."""
    source = Path(code_file)
    output_path = Path(rst_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    module_name = _module_name(str(source), source_root)
    members = extract_public_members(source.read_text(encoding="utf-8"))
    is_initializer = source.name == "__init__.py"
    relative_source = os.path.relpath(os.path.abspath(str(source)), os.path.abspath(str(source_root))).replace(
        "\\", "/"
    )
    is_root_initializer = is_initializer and relative_source.count("/") == 1

    with StringIO() as output:
        if source.stem.startswith("_") and not is_initializer:
            print(":orphan:", file=output)
            print("", file=output)

        title = _escape_rst(module_name)
        print(title, file=output)
        print("=" * max(56, len(title)), file=output)
        print("", file=output)
        print(".. currentmodule:: %s" % module_name, file=output)
        print("", file=output)
        print(".. automodule:: %s" % module_name, file=output)
        print("", file=output)
        print("", file=output)

        if is_initializer and not is_root_initializer:
            _print_package_toctree(output, str(source))

        _print_members(output, members)
        _write_text_lf(output_path, normalize_rst_document(output.getvalue()))


def main():
    parser = argparse.ArgumentParser(description="Generate one Sphinx RST API page")
    parser.add_argument("-i", "--input", required=True, help="Python source file")
    parser.add_argument("-o", "--output", required=True, help="RST output file")
    parser.add_argument("--source-root", default=".", help="Root used to derive the importable module name")
    arguments = parser.parse_args()
    convert_code_to_rst(arguments.input, arguments.output, arguments.source_root)


if __name__ == "__main__":
    main()
