# P1 budget control -- BYPASSABLE (lighthouse SpendCap, settled-only).
# The spend decision charges settled-only (ignores in-flight requests), so a
# parallel-fire burst of in-flight requests can overshoot the cap.
def can_spend(settled, amount=100, cap=200):
    """Admit a request if settled + this one stays within cap (ignores in-flight)."""
    return (settled + amount) <= cap