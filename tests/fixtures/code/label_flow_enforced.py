# P1 label/flow control -- ENFORCED (lighthouse NoExfiltration).
# The egress decision guards on the data label: labeled (private) data may
# reach only the allowed channels.
def can_egress(holding_private, channel, allowed):
    """Allow egress only when not holding private data, or to an allowed channel."""
    return (not holding_private) or (channel in allowed)