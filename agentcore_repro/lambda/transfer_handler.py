# -*- coding: utf-8 -*-
"""transfer_handler.py -- mock bank-transfer backend for the GAP-4 repro.

Deployed as an AWS Lambda behind the AgentCore Gateway (MCP target
``TransferTarget``, tool ``transfer``).  It is deliberately trivial: accept
an ``amount`` (integer), "settle" the transfer, return a receipt.  It also
prints a structured SETTLE line to CloudWatch Logs so the evidence step can
prove the transfer actually executed (and count settlements).

The handler is permissive about the invoke envelope: it accepts a flat
``{"amount": N}`` body or an MCP/JSON-RPC envelope such as
``{"params": {"arguments": {"amount": N}}}``.  It never fails on shape;
it only fails if ``amount`` is missing or not a positive integer (the
policy under test expects the tool to work for 1..2000).
"""

import json
import uuid


def _extract_amount(event):
    if not isinstance(event, dict):
        raise ValueError("no event")
    # flat body
    if "amount" in event:
        return event["amount"]
    # MCP tools/call envelope
    params = event.get("params")
    if isinstance(params, dict):
        args = params.get("arguments")
        if isinstance(args, dict) and "amount" in args:
            return args["amount"]
        if "amount" in params:
            return params["amount"]
    # some gateways pass the arguments object directly under "input"
    for key in ("input", "body", "request"):
        v = event.get(key)
        if isinstance(v, dict) and "amount" in v:
            return v["amount"]
    raise ValueError("amount not found in envelope: %s" % _safe(event))


def _safe(event):
    try:
        return json.dumps(event)[:200]
    except Exception:
        return str(event)[:200]


def handler(event, context):
    amount = _extract_amount(event)
    try:
        amount = int(amount)
    except (TypeError, ValueError):
        raise ValueError("amount must be an integer, got: %r" % (amount,))
    if amount <= 0:
        raise ValueError("amount must be positive, got: %d" % amount)
    tx_id = "rot-" + uuid.uuid4().hex[:12]
    # Structured, greppable settlement line (CloudWatch Logs evidence).
    print("SETTLE txId=%s amount=%d status=SETTLED" % (tx_id, amount))
    return {
        "txId": tx_id,
        "amount": amount,
        "status": "SETTLED",
        "currency": "USD",
        "mock": True,
    }