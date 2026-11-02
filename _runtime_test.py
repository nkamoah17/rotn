"""Drive `rot runtime eval` for both the BLOCKED and ALLOWED states (clean argv)."""
import subprocess, sys, os
os.chdir(r"c:\Users\jeren\Documents\KAMANU\ROTN")

def run(state):
    args = [sys.executable, "-m", "rot", "runtime", "eval",
            "--tool", "spend", "--arg", "amount=100", "--state", state]
    r = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return r.returncode, r.stdout.decode("utf-8", "replace")

code_b, out_b = run('{"completed": 0, "inflight": 3}')
print("BLOCKED (inflight=3): exit", code_b, "(1 = BLOCKED, correct verdict)")

code_a, out_a = run('{"completed": 0, "inflight": 0}')
print("ALLOWED (inflight=0): exit", code_a, "(0 = ALLOWED)")
print("ALLOWED stdout tail:", out_a[-500:])
