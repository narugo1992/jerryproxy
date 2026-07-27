import os
import sys

sys.path.insert(0, os.path.abspath("../.."))

from jerryproxy.config.meta import __VERSION__


project = "JerryProxy"
author = "narugo1992"
copyright = "2026, narugo1992"
version = __VERSION__
release = __VERSION__

extensions = ["sphinx.ext.autodoc", "sphinx.ext.intersphinx", "sphinx.ext.viewcode"]
templates_path = ["_templates"]
exclude_patterns = []
html_theme = "sphinx_rtd_theme"
html_static_path = []
master_doc = "index"
