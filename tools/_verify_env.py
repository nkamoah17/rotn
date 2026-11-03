# -*- coding: utf-8 -*-
"""tools/_verify_env.py -- one-shot Phase-0 environment self-check (not shipped)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rot import config  # noqa: E402


def main():
    c = config.Config()
    print("jar       =", c.tlc_jar_path())
    print("java_cmd  =", c.java_cmd)
    print("TLC avail =", c.tlc_available())
    return 0 if c.tlc_available() else 1


if __name__ == "__main__":
    sys.exit(main())
