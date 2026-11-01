# -*- coding: utf-8 -*-
"""Remove the ladder/ab subparsers + dispatch entries from rot/__main__.py."""
import io

path = "rot/__main__.py"
with io.open(path, "r", encoding="utf-8", newline="") as f:
    content = f.read()

NL = "\r\n"  # file uses CRLF
lines = content.split("\n")
# normalize: work with the raw lines (they may end with \r)

# Find the ladder subparser start and the ab subparser end.
start_idx = None
for i, l in enumerate(lines):
    if l.strip() == '"ladder",':
        # the sub.add_parser( line is the previous line
        start_idx = i - 1
        break
if start_idx is None:
    raise SystemExit("ladder subparser not found")

# Find the end: the line with 'help="suppress the human report (with --json)")'
end_idx = None
for i in range(start_idx, len(lines)):
    if 'suppress the human report (with --json)' in lines[i]:
        end_idx = i
        break
if end_idx is None:
    raise SystemExit("ab subparser end not found")

# Replace lines[start_idx .. end_idx] with a comment.
comment = (
    '    # NOTE: the `ladder` and `ab` commands are research commands that live in' + "\n"
    '    # the rotn-research repo; they are intentionally NOT registered here so' + "\n"
    '    # that `rot --help` lists only product commands (Phase A boundary).' + "\n"
)
new_lines = lines[:start_idx] + comment.split("\n")[:-1] + lines[end_idx + 1:]
new_content = "\n".join(new_lines)

# Remove the dispatch entries: '"ladder": cmd_ladder,' and '"ab": cmd_ab}'
# The dispatch line is:  "ab": cmd_ab}[args.command](args)
new_content = new_content.replace(
    NL + '            "ladder": cmd_ladder,', "")
new_content = new_content.replace(
    '            "doctor": cmd_doctor,' + NL + '            "ladder": cmd_ladder,',
    '            "doctor": cmd_doctor,')
# handle the '"ab": cmd_ab}' -> '"doctor": cmd_doctor}' (already handled above if ladder removed)
# Ensure the dispatch ends with doctor
if '"ab": cmd_ab}' in new_content:
    new_content = new_content.replace('"ab": cmd_ab}', '"doctor": cmd_doctor}')
    # but we must make sure doctor is present exactly once before it
# The original dispatch:
#   ...
#   "doctor": cmd_doctor,
#   "ladder": cmd_ladder,
#   "ab": cmd_ab}[args.command](args)
# After removing ladder line, it becomes:
#   "doctor": cmd_doctor,
#   "ab": cmd_ab}[args.command](args)
# We want:
#   "doctor": cmd_doctor}[args.command](args)
new_content = new_content.replace(
    '            "doctor": cmd_doctor,' + NL + '            "ab": cmd_ab}[args.command](args)',
    '            "doctor": cmd_doctor}[args.command](args)')

with io.open(path, "w", encoding="utf-8", newline="") as f:
    f.write(new_content)

print("removed ladder/ab subparsers + dispatch entries")
print("ladder in file:", '"ladder"' in new_content)
print("cmd_ab dispatch:", '"ab": cmd_ab' in new_content)
