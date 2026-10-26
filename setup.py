# -*- coding: utf-8 -*-
"""setup.py -- packaging for the ROTN temporal policy verification engine.

ROTN is a pure-stdlib (zero-dependency) Python package that verifies
temporal safety policies against bounded state-space models using three
independent engines (SMT/Z3, TLC, and policy-direct).  It ships with a
``rot`` console script for the product-grade CLI.

Python 3.6 compatible.  No external dependencies.
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
    return "0.1.0"


setup(
    name="rotn",
    version=_read_version(),
    description=(
        "ROTN -- temporal policy verification engine. "
        "Three-engine cross-check (SMT/Z3 + TLC + policy-direct) with "
        "deterministic counterexample generation."
    ),
    long_description=(
        "ROTN verifies temporal safety policies (Dogwood, Cedar, .dw "
        "spend-cap) against bounded state-space models using three "
        "independent engines.  A VIOLATED verdict requires all three "
        "engines to agree on the same counterexample state -- "
        "soundness-first by construction.\n\n"
        "Pure stdlib, zero external dependencies, Python 3.6+."
    ),
    long_description_content_type="text/plain",
    author="KAMANU",
    license="MIT",
    python_requires=">=3.6",
    packages=find_packages(exclude=[
        "tests", "tests.*",        # top-level test tree (not shipped)
        "rot.tests", "rot.tests.*",  # in-package Java-build integration tests
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
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Software Development :: Testing",
        "Operating System :: OS Independent",
        "Environment :: Console",
    ],
)
