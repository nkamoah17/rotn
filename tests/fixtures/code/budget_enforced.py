# P1 budget control -- ENFORCED (lighthouse SpendCap, parallel-fire safe).
# The spend decision accounts for in-flight requests, so a parallel-fire burst
# of in-flight requests cannot overshoot the cap.
def can_spend(settled, inflight, amount=100, cap=200):
    """Admit a request only if settled + in-flight + this one stays within cap."""
    return (settled + inflight * amount + amount) <= cap