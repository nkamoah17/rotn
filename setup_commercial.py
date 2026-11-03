# -*- coding: utf-8 -*-
"""setup_commercial.py -- packaging for the ROTN **commercial** layer.

This is the ``rotn-commercial`` distribution: the "thick" commercial layer
(``rot.commercial``: the runtime coach as a service, the LangChain adapter, the
MCP ``tools/call`` gateway, the fleet near-miss aggregate, the G8 behavioral
audit, and the Lethal-Trifecta risk surface).

It is **Apache-2.0** (like the rest of the repo) -- the paid product is the
**hosted service** (the cloud version of ``rot runtime serve`` + the signed
attestations), which is NOT in this repo.  See ``docs/licensing.md``.

It depends on the ``rotn`` core (``pip install rotn``) and ships the
``rot.commercial`` sub-packages.  Install order:

    pip install rotn            # the Apache-2.0 core (proof wedge)
    pip install rotn-commercial # the Apache-2.0 commercial layer

Python 3.8+.  Zero *external* runtime deps (LangChain / MCP are
optional, imported lazily only when the corresponding command is used).
"""

from setuptools import setup, find_packages
import os


def _read_version():
    """Read ``rot.__version__`` from the core (single source of truth)."""
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
    name="rotn-commercial",
    version=_read_version(),
    description=(
        "ROTN -- the commercial layer (Product 2/3): the runtime coach as a "
        "service, fleet near-miss learning, MCP gateway, behavioral audit, and "
        "risk forecasting. Apache-2.0; depends on the Apache-2.0 core "
        "(``rotn``)."
    ),
    long_description=(
        "# ROTN Commercial\n\n"
        "The **commercial** layer of ROTN -- the service plane that wraps the "
        "Apache-2.0 core.  All local code in the repo is **Apache-2.0**; the "
        "paid product is the **hosted service** (the cloud version of "
        "``rot runtime serve`` + the signed attestations), which is NOT in "
        "this repo.  Depends on the Apache-2.0 core (``pip install rotn``) "
        "and ships the ``rot.commercial`` sub-packages.  See "
        "``docs/licensing.md`` for the full position.\n\n"
        "Pure stdlib core; LangChain and MCP are optional and imported lazily."
    ),
    long_description_content_type="text/markdown",
    author="ROTN",
    url="https://github.com/nkamoah17/rotn",
    project_urls={
        "Repository": "https://github.com/nkamoah17/rotn",
        "Licensing": "https://github.com/nkamoah17/rotn/blob/main/docs/licensing.md",
    },
    license="Apache-2.0",
    python_requires=">=3.8",
    # Only the commercial sub-packages -- the Apache-2.0 core comes from ``rotn``.
    packages=find_packages(include=["rot.commercial", "rot.commercial.*"]),
    # The free core is a hard dependency (this layer is a plugin on it).
    install_requires=["rotn"],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Operating System :: OS Independent",
        "Environment :: Console",
    ],
)