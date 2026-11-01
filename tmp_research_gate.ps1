$ErrorActionPreference = 'Stop'
$p = 'c:\Users\jeren\Documents\KAMANU\ROTN\rot\__main__.py'
$lines = [System.IO.File]::ReadAllLines($p)

function Find-Line($arr, $pattern, $from) {
    for ($k = $from; $k -lt $arr.Length; $k++) {
        if ($arr[$k] -match $pattern) { return $k }
    }
    throw "pattern not found: $pattern"
}

$ladder = Find-Line $lines '^def cmd_ladder\(args\):' 0
$ab     = Find-Line $lines '^def cmd_ab\(args\):' $ladder
$main   = Find-Line $lines '^def main\(argv=None\):' $ab

$ladderStub = @'
def cmd_ladder(args):
    """`ladder` is a research command -- it lives in the rotn-research repo.

    The product build does not carry the research plane (Phase A boundary),
    so invoking it here is a hard error with a clear pointer (exit 3).
    """
    print("ERROR: 'rot ladder' is a research command and is not part of "
          "this build.\n"
          "       It lives in the rotn-research repo (see its README and "
          "pipeline CLI).", file=sys.stderr)
    return EXIT_ERROR
'@ -split "`n"

$abStub = @'
def cmd_ab(args):
    """`ab` is a research command -- it lives in the rotn-research repo.

    The product build does not carry the research plane (Phase A boundary),
    so invoking it here is a hard error with a clear pointer (exit 3).
    """
    print("ERROR: 'rot ab' is a research command and is not part of "
          "this build.\n"
          "       It lives in the rotn-research repo (see its README and "
          "pipeline CLI).", file=sys.stderr)
    return EXIT_ERROR
'@ -split "`n"

$new = New-Object System.Collections.ArrayList
$new.AddRange($lines[0..($ladder-1)])
$new.AddRange($ladderStub)
$new.Add('')
$new.Add('')
$new.AddRange($abStub)
$new.Add('')
$new.Add('')
$new.AddRange($lines[$main..($lines.Length-1)])

# --- intercept ladder/ab in main(), before the parser is built -------------
$mdoc = Find-Line $new 'ROTN CLI entry point' 0
$intercept = @'
    # RESEARCH commands (Phase A boundary): `ladder` and `ab` live in the
    # rotn-research repo.  They are deliberately NOT product subcommands, so
    # `rot --help` lists only product commands; invoking one yields the clear
    # "research command, not in this build" message (exit 3), not an opaque
    # argparse error.
    if argv and argv[0] in ("ladder", "ab"):
        return {"ladder": cmd_ladder, "ab": cmd_ab}[argv[0]](
            argparse.Namespace(command=argv[0]))
'@ -split "`n"
$ins = New-Object System.Collections.ArrayList
$ins.AddRange($new[0..$mdoc])
$ins.AddRange($intercept)
$ins.AddRange($new[($mdoc+1)..($new.Length-1)])
$new = $ins

# --- replace the hidden-subparser block with a NOTE ------------------------
$note = Find-Line $new 'RESEARCH commands: .ladder. and .ab. live in the' 0
# the block is: 5 comment lines + 4 add_parser lines
$ins = New-Object System.Collections.ArrayList
$ins.AddRange($new[0..($note-1)])
$ins.Add('    # NOTE: the `ladder` and `ab` commands are research commands that live in')
$ins.Add('    # the rotn-research repo.  They are intercepted in main() before parsing')
$ins.Add('    # (and are deliberately not subcommands) so `rot --help` lists only product')
$ins.Add('    # commands; running one yields the exit-3 research gate.')
$ins.AddRange($new[($note+9)..($new.Length-1)])
$new = $ins

# --- fix the dispatch dict (drop the unreachable ladder/ab entries) --------
$d = Find-Line $new '"ladder": cmd_ladder, "ab": cmd_ab' 0
$new[$d] = '            "doctor": cmd_doctor}[args.command](args)'

[System.IO.File]::WriteAllLines($p, $new, (New-Object System.Text.UTF8Encoding($false)))
Write-Output 'main.py research gate: done'
