# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

import datetime
import os
import sys
from typing import List

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
# import os
# import sys
# sys.path.insert(0, os.path.abspath('.'))
import sphinx_rtd_theme  # noqa

sys.path.insert(0, os.path.abspath("../common"))
sys.path.insert(0, os.path.abspath("../scan"))
sys.path.insert(0, os.path.abspath(".."))
sys.path.insert(0, os.path.abspath("."))


# -- Project information -----------------------------------------------------

project = "mailgoose"
copyright = f"{datetime.datetime.now().year}, CERT Polska"
author = "CERT Polska"

# The full version, including alpha/beta/rc tags
release = "1.3.14"

latex_engine = "xelatex"

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "sphinx_rtd_theme",
    "sphinx.ext.graphviz",
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "generate_config_docs",
]

graphviz_output_format = "svg"

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store", "venv"]


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "sphinx_rtd_theme"

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path: List[str] = []


html_css_files = [
    "style.css",
]
