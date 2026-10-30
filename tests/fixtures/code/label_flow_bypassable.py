# P1 label/flow control -- BYPASSABLE (lighthouse NoExfiltration).
# The egress decision ignores the data label (unconditional allow), so
# labeled data can be exfiltrated to any channel.
def can_egress(holding_private, channel, allowed):
    """Allow egress unconditionally (ignores whether private data is held)."""
    return True