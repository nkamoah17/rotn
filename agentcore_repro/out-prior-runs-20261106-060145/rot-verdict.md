# ROTN catch / fix / prove (GAP-4)

| check | result |
|---|---|
| buggy policy VIOLATED (exit 1 expected) | PASS |
| correct policy PROVEN (exit 0 expected) | PASS |
| live AWS: 3 admitted, $300 > $200 cap | PASS |

## Local witness (buggy, K=3)

```
{
  "dw_window": "24h",
  "max_inflight": 3,
  "n_steps": 1,
  "policy_source": "C:\\Users\\jeren\\Documents\\KAMANU\\ROTN\\samples\\spendcap-buggy.dw",
  "property_kind": "safety",
  "property_name": "spendcap_within_cap",
  "target": "policy-spendcap-buggy.dw",
  "tools_source": null,
  "verdict": "violated",
  "window": 4,
  "witness": {
    "completed": 0,
    "inflight": 3
  }
}
```

## Pipeline tail (buggy)

```
--------------------------------------------------------------
  ROTN policy verification (safety)
--------------------------------------------------------------
  target    : policy-spendcap-buggy.dw
  property  : spendcap_within_cap
  source    : C:\Users\jeren\Documents\KAMANU\ROTN\samples\spendcap-buggy.dw
  n-steps   : 1
  max-inflt : 3 (bounded concurrency pool K)
  window    : 4 (bounded event count W; 24h)
  verdict   : VIOLATED
  witness   : {"completed": 0, "inflight": 3}
  report    : C:\Users\jeren\Documents\KAMANU\ROTN\agentcore_repro\out\rot-live-buggy\policy-spendcap-buggy.dw_spendcap_within_cap.json
--------------------------------------------------------------

```

## Pipeline tail (correct)

```
--------------------------------------------------------------
  ROTN policy verification (safety)
--------------------------------------------------------------
  target    : policy-spendcap-correct.dw
  property  : spendcap_within_cap
  source    : C:\Users\jeren\Documents\KAMANU\ROTN\samples\spendcap-correct.dw
  n-steps   : 1
  max-inflt : 3 (bounded concurrency pool K)
  window    : 4 (bounded event count W; 24h)
  verdict   : PROVEN
  report    : C:\Users\jeren\Documents\KAMANU\ROTN\agentcore_repro\out\rot-live-correct\policy-spendcap-correct.dw_spendcap_within_cap.json
--------------------------------------------------------------

```

## Live evidence

```
{
  "admitted_count": 3,
  "amount": 100,
  "committed_usd": 300,
  "denied_count": 0,
  "fired_at_utc": "2026-11-05T02:18:29Z",
  "nfires": 3,
  "path": "/mcp",
  "phase": "buggy-deployed",
  "results": [
    {
      "amount": 100,
      "elapsed_s": 3.36,
      "exit_code": 0,
      "fire": 1,
      "path": "/mcp",
      "response_file": "C:\\Users\\jeren\\Documents\\KAMANU\\ROTN\\agentcore_repro\\out\\fire-1.json",
      "session_id": "18884ad6-de14-40ce-a016-375a39573fd0",
      "stderr_tail": "status=200 content-type=application/json runtime-session-id=- mcp-session-id=- mcp-protocol-version=- request-id=4b897060-9e79-4e46-a841-07bcc828320e complete=true bytes=193\n",
      "stdout_tail": "",
      "tool": "TransferTarget___transfer",
      "verdict": "ADMITTED"
    },
    {
      "amount": 100,
      "elapsed_s": 0.0,
      "exit_code": 0,
      "fire": 2,
      "path": "/mcp",
      "response_file": "C:\\Users\\jeren\\Documents\\KAMANU\\ROTN\\agentcore_repro\\out\\fire-2.json",
      "session_id": "18884ad6-de14-40ce-a016-375a39573fd0",
      "stderr_tail": "status=200 content-type=application/json runtime-session-id=- mcp-session-id=- mcp-protocol-version=- request-id=307cd4b4-b169-49ac-addd-d8a0c102515f complete=true bytes=193\n",
      "stdout_tail": "",
      "tool": "TransferTarget___transfer",
      "verdict": "ADMITTED"
    },
    {
      "amount": 100,
      "elapsed_s": 0.0,
      "exit_code": 0,
      "fire": 3,
      "path": "/mcp",
      "response_file": "C:\\Users\\jeren\\Documents\\KAMANU\\ROTN\\agentcore_repro\\out\\fire-3.json",
      "session_id": "18884ad6-de14-40ce-a016-375a39573fd0",
      "stderr_tail": "status=200 content-type=application/json runtime-session-id=- mcp-session-id=- mcp-protocol-version=- request-id=09279375-d5b6-4089-b176-be68951eb9dd complete=true bytes=193\n",
      "stdout_tail": "",
      "tool": "TransferTarget___transfer",
      "verdict": "ADMITTED"
    }
  ],
  "session_id": "18884ad6-de14-40ce-a016-375a39573fd0",
  "tool": "TransferTarget___transfer"
}
```

