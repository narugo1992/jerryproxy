"""Generate the English top-level Sphinx API index."""

import argparse
import os
import re
from io import StringIO
from pathlib import Path


def _natural_key(value):
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", value)]


def _api_entries(input_dir):
    entries = []
    for child in Path(input_dir).iterdir():
        if child.is_dir() and (child / "__init__.py").is_file():
            if not child.name.startswith("_"):
                entries.append("api_doc/%s/index" % child.name)
        elif child.is_file() and child.suffix == ".py":
            if not child.stem.startswith("_"):
                entries.append("api_doc/%s" % child.stem)
    return sorted(entries, key=_natural_key)


def normalize_rst_document(text):
    """Return a non-empty document with exactly one trailing newline."""
    stripped = text.rstrip()
    return "%s\n" % stripped if stripped else ""


def _write_text_lf(path, text):
    with Path(path).open("w", encoding="utf-8", newline="\n") as output:
        output.write(text)


def generate_rst_index(input_dir, output_file):
    """Generate the English API landing page and module toctree."""
    entries = _api_entries(input_dir)
    with StringIO() as output:
        print("API Reference", file=output)
        print("=============", file=output)
        print("", file=output)
        print("This page is generated from the public Python modules under", file=output)
        print("``jerryproxy/``. Run ``make rst_auto`` after changing public", file=output)
        print("modules, classes, functions, or data objects.", file=output)
        print("", file=output)
        print(".. toctree::", file=output)
        print("   :maxdepth: 2", file=output)
        print("   :caption: Python API", file=output)
        print("   :hidden:", file=output)
        print("", file=output)
        print("   api_doc/index", file=output)
        for entry in entries:
            print("   %s" % entry, file=output)
        print("", file=output)
        print("* :doc:`api_doc/index`", file=output)
        for entry in entries:
            print("* :doc:`%s`" % entry, file=output)

        _write_text_lf(output_file, normalize_rst_document(output.getvalue()))


def main():
    parser = argparse.ArgumentParser(description="Generate the Sphinx API index")
    parser.add_argument("-i", "--input-dir", required=True, help="Python package root")
    parser.add_argument("-o", "--output-dir", required=True, help="Sphinx source root")
    arguments = parser.parse_args()
    os.makedirs(arguments.output_dir, exist_ok=True)
    output_file = os.path.join(arguments.output_dir, "api_doc.rst")
    generate_rst_index(arguments.input_dir, output_file)
    print("Generated: %s" % output_file)


if __name__ == "__main__":
    main()
