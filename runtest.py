# -*- coding: utf-8 -*-
"""Run a python test module and capture all output to a file (PS-friendly)."""
import io
import runpy
import sys

target = sys.argv[1]
out_path = sys.argv[2]
sys.argv = [target]  # the test under test must see a clean argv
buf = io.StringIO()
old_out, old_err = sys.stdout, sys.stderr
sys.stdout = sys.stderr = buf
code = 0
try:
    runpy.run_path(target, run_name="__main__")
except SystemExit as e:
    code = e.code if isinstance(e.code, int) else 1
except Exception:
    import traceback
    buf.write(traceback.format_exc())
    code = 1
finally:
    sys.stdout, sys.stderr = old_out, old_err
with io.open(out_path, "w", encoding="utf-8") as f:
    f.write("EXIT=%r\n" % (code,))
    f.write(buf.getvalue())
