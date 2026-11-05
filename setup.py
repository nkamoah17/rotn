# -*- coding: utf-8 -*-
"""setup.py -- packaging for the ROTN temporal policy verification engine.

ROTN is a pure-stdlib (zero-dependency) Python package that verifies
temporal safety policies against bounded state-space models using three
independent engines (SMT/Z3, TLC, and policy-direct -- the two independent
model checkers decide, with the spend-cap-specific policy-direct engine as
the third, model-independent leg and offline fallback).  It ships with a
``rot`` console script for the product-grade CLI.

Python 3.8+.  No external dependencies.
"""

from setuptools import setup, find_packages
import os


def _read_version():
    """Read ``rot.__version__`` without importing the package.

    Keeps setup.py safe to run in minimal build environments (no need to
    import the engine) while preserving a single source of truth for the
    version string.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    init = os.path.join(here, "rot", "__init__.py")
    try:
        with open(init, "r") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("__version__"):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    except (IOError, OSError):
        pass
    return "0.2.0"


setup(
    name="rotn",
    version=_read_version(),
    description=(
        "nkamoah17/rotn -- verify an AI agent's tool policy (Dogwood or "
        "an MCP manifest) with a built-in pure-stdlib engine + optional "
        "Z3/TLC/Apalache cross-checks; engine-labeled verdicts; "
        "deterministic, hashed trace; SOC 2 / AIUC control mapping; zero "
        "runtime deps."
    ),
    long_description=(
        "<p align=\"center\">"
        "<img src=\"assets/caravel_logo.jpeg\" alt=\"ROTN\" width=\"160\"/>"
        "</p>\n\n"
        "# ROTN — Regression-detection Oracle via Trace Non-emptiness\n\n"
        "**ROTN** — *Agents are replacing the software that used to "
        "enforce our rules. We make the rules explicit, prove the policy "
        "holds even when the model attempts to break it, and coach the "
        "agent back in bounds when it does.*\n\n"
        "ROTN ingests an AI agent's tool policy (Dogwood *or* a standard "
        "MCP manifest) and verifies it with a **built-in, pure-stdlib "
        "default engine** (a bounded state-space model finder), with "
        "**optional Z3 / TLC / Apalache cross-checks** that degrade to a "
        "skip or an honest `UNKNOWN` when absent, and a bounded re-check "
        "loop. Every **verdict is engine-labeled**, so you always know "
        "which engine(s) produced it. ROTN maps findings to SOC 2 / AIUC "
        "controls, bounds "
        "depth by a user-set `--depth` bound, and emits a deterministic, "
        "hashed trace that "
        "replays as an interactive proof on GitHub Pages.\n\n"
        "Pure stdlib, zero external dependencies, Python 3.8+.\n\n"
        "Repository: [nkamoah17/rotn]"
        "(https://github.com/nkamoah17/rotn)\n"
    ),
    long_description_content_type="text/markdown",
    author="ROTN",
    url="https://github.com/nkamoah17/rotn",
    project_urls={
        "Repository": "https://github.com/nkamoah17/rotn",
        "Issues": "https://github.com/nkamoah17/rotn/issues",
        "Documentation": "https://nkamoah17.github.io/rotn/",
    },
    license="Apache-2.0",
    python_requires=">=3.8",
    packages=find_packages(exclude=[
        "tests", "tests.*",        # top-level test tree (not shipped)
        "rot.tests", "rot.tests.*",  # in-package Java-build integration tests
        # The **commercial** layer is a separate distribution (``rotn-commercial``,
        # Apache-2.0) -- it ships on the Apache-2.0 core.
        "rot.commercial", "rot.commercial.*",
    ]),
    package_data={
        # Include .dw fixture files if they are inside the package tree.
        # (The 59 AWS Dogwood fixtures live under tests/fixtures and are
        # NOT shipped with the package -- they are test-only.)
    },
    install_requires=[],  # zero external dependencies
    entry_points={
        "console_scripts": [
            "rot=rot.__main__:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Software Development :: Testing",
        "Operating System :: OS Independent",
        "Environment :: Console",
    ],
)
