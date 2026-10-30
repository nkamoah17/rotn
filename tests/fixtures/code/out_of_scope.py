# OUT OF SCOPE: no P1 control (budget or label/flow) is present.
# This module must be reported OUT_OF_SCOPE (E2), never claimed and never a
# silent UNKNOWN.
def greet(name):
    """A greeting -- a plain helper with no security-relevant control."""
    return "hello, " + name