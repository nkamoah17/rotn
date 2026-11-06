# GAP-4 live evidence

- captured: 2026-11-05T02:41:40Z
- region: us-east-1
- gateway: arn:aws:bedrock-agentcore:us-east-1:626756230713:gateway/rot-spendcap-gw-e0umswk6ss
- fires: 3 x $100, session 18884ad6-de14-40ce-a016-375a39573fd0
- admitted: 3, denied: 0, committed: $300
- lambda SETTLED total: $300 (consistent: True)

## Lambda settle lines
- rot-21c39914a00c  $100  SETTLED
- rot-1e0ff80a5e18  $100  SETTLED
- rot-306def820a18  $100  SETTLED

## CloudWatch metrics (last 15m)
- DenyDecisions [TargetResource=rot-spendcap-gw-e0umswk6ss, ToolName=TransferTarget___transfer, OperationName=PartiallyAuthorizeActions, Mode=ENFORCE]: [{'Timestamp': '2026-11-05T02:00:00+00:00', 'SampleCount': 1.0, 'Sum': 1.0, 'Unit': 'Milliseconds'}]
- DenyDecisions [TargetResource=rot-spendcap-gw-e0umswk6ss, ToolName=TransferTarget___transfer, OperationName=PartiallyAuthorizeActions, Mode=ENFORCE, PolicyEngine=rot_spendcap_engine-rzhlj_2hg9]: [{'Timestamp': '2026-11-05T02:00:00+00:00', 'SampleCount': 1.0, 'Sum': 1.0, 'Unit': 'Milliseconds'}]
- DenyDecisions [TargetResource=rot-spendcap-gw-e0umswk6ss, ToolName=TransferTarget___transfer, OperationName=PartiallyAuthorizeActions, PolicyEngine=rot_spendcap_engine-rzhlj_2hg9]: [{'Timestamp': '2026-11-05T02:00:00+00:00', 'SampleCount': 1.0, 'Sum': 1.0, 'Unit': 'Milliseconds'}]
- DenyDecisions [TargetResource=rot-spendcap-gw-e0umswk6ss, ToolName=TransferTarget___transfer, OperationName=PartiallyAuthorizeActions]: [{'Timestamp': '2026-11-05T02:00:00+00:00', 'SampleCount': 1.0, 'Sum': 1.0, 'Unit': 'Milliseconds'}]
- Latency [TargetResource=rot-spendcap-gw-e0umswk6ss, OperationName=PartiallyAuthorizeActions]: [{'Timestamp': '2026-11-05T02:00:00+00:00', 'SampleCount': 1.0, 'Sum': 19.0, 'Unit': 'Milliseconds'}]
- Throttles [Resource=arn:aws:bedrock-agentcore:us-east-1:626756230713:gateway/rot-spendcap-gw-e0umswk6ss, Operation=InvokeGateway, Protocol=MCP]: [{'Timestamp': '2026-11-05T02:00:00+00:00', 'SampleCount': 1.0, 'Sum': 0.0, 'Unit': 'Count'}, {'Timestamp': '2026-11-05T02:18:00+00:00', 'SampleCount': 3.0, 'Sum': 0.0, 'Unit': 'Count'}]
- SystemErrors [Resource=arn:aws:bedrock-agentcore:us-east-1:626756230713:gateway/rot-spendcap-gw-e0umswk6ss, Operation=InvokeGateway, Protocol=MCP]: [{'Timestamp': '2026-11-05T02:00:00+00:00', 'SampleCount': 1.0, 'Sum': 0.0, 'Unit': 'Count'}, {'Timestamp': '2026-11-05T02:18:00+00:00', 'SampleCount': 3.0, 'Sum': 0.0, 'Unit': 'Count'}]
- UserErrors [Resource=arn:aws:bedrock-agentcore:us-east-1:626756230713:gateway/rot-spendcap-gw-e0umswk6ss, Operation=InvokeGateway, Protocol=MCP]: [{'Timestamp': '2026-11-05T02:00:00+00:00', 'SampleCount': 1.0, 'Sum': 0.0, 'Unit': 'Count'}, {'Timestamp': '2026-11-05T02:18:00+00:00', 'SampleCount': 3.0, 'Sum': 0.0, 'Unit': 'Count'}]
- UserErrors [Resource=arn:aws:bedrock-agentcore:us-east-1:626756230713:gateway/rot-spendcap-gw-e0umswk6ss, Operation=InvokeGateway, Method=tools/list, Protocol=MCP]: [{'Timestamp': '2026-11-05T02:00:00+00:00', 'SampleCount': 1.0, 'Sum': 0.0, 'Unit': 'Count'}]
- Latency [Resource=arn:aws:bedrock-agentcore:us-east-1:626756230713:gateway/rot-spendcap-gw-e0umswk6ss, Operation=InvokeGateway, Protocol=MCP]: [{'Timestamp': '2026-11-05T02:00:00+00:00', 'SampleCount': 1.0, 'Sum': 89.0, 'Unit': 'Milliseconds'}, {'Timestamp': '2026-11-05T02:18:00+00:00', 'SampleCount': 3.0, 'Sum': 1426.0, 'Unit': 'Milliseconds'}]
- Latency [Resource=arn:aws:bedrock-agentcore:us-east-1:626756230713:gateway/rot-spendcap-gw-e0umswk6ss, Operation=InvokeGateway, Method=tools/list, Protocol=MCP]: [{'Timestamp': '2026-11-05T02:00:00+00:00', 'SampleCount': 1.0, 'Sum': 89.0, 'Unit': 'Milliseconds'}]
- Throttles [Resource=arn:aws:bedrock-agentcore:us-east-1:626756230713:gateway/rot-spendcap-gw-e0umswk6ss, Operation=InvokeGateway, Method=tools/list, Protocol=MCP]: [{'Timestamp': '2026-11-05T02:00:00+00:00', 'SampleCount': 1.0, 'Sum': 0.0, 'Unit': 'Count'}]
- SystemErrors [Resource=arn:aws:bedrock-agentcore:us-east-1:626756230713:gateway/rot-spendcap-gw-e0umswk6ss, Operation=InvokeGateway, Method=tools/list, Protocol=MCP]: [{'Timestamp': '2026-11-05T02:00:00+00:00', 'SampleCount': 1.0, 'Sum': 0.0, 'Unit': 'Count'}]
- AllowDecisions [Policy=rotspendcap-nrjoll9d_k, TargetResource=rot-spendcap-gw-e0umswk6ss, OperationName=AuthorizeAction, Mode=ENFORCE, PolicyEngine=rot_spendcap_engine-rzhlj_2hg9]: [{'Timestamp': '2026-11-05T02:18:00+00:00', 'SampleCount': 3.0, 'Sum': 3.0, 'Unit': 'Count'}]
- AllowDecisions [TargetResource=rot-spendcap-gw-e0umswk6ss, OperationName=AuthorizeAction, Mode=ENFORCE, PolicyEngine=rot_spendcap_engine-rzhlj_2hg9]: [{'Timestamp': '2026-11-05T02:18:00+00:00', 'SampleCount': 3.0, 'Sum': 3.0, 'Unit': 'Count'}]
- AllowDecisions [Policy=rotspendcap-nrjoll9d_k, TargetResource=rot-spendcap-gw-e0umswk6ss, OperationName=AuthorizeAction, PolicyEngine=rot_spendcap_engine-rzhlj_2hg9]: [{'Timestamp': '2026-11-05T02:18:00+00:00', 'SampleCount': 3.0, 'Sum': 3.0, 'Unit': 'Count'}]
- AllowDecisions [Policy=rotspendcap-nrjoll9d_k, TargetResource=rot-spendcap-gw-e0umswk6ss, OperationName=AuthorizeAction]: [{'Timestamp': '2026-11-05T02:18:00+00:00', 'SampleCount': 3.0, 'Sum': 3.0, 'Unit': 'Count'}]
- AllowDecisions [Policy=rotspendcap-nrjoll9d_k, TargetResource=rot-spendcap-gw-e0umswk6ss, OperationName=AuthorizeAction, Mode=ENFORCE]: [{'Timestamp': '2026-11-05T02:18:00+00:00', 'SampleCount': 3.0, 'Sum': 3.0, 'Unit': 'Count'}]
- AllowDecisions [TargetResource=rot-spendcap-gw-e0umswk6ss, OperationName=AuthorizeAction]: [{'Timestamp': '2026-11-05T02:18:00+00:00', 'SampleCount': 3.0, 'Sum': 3.0, 'Unit': 'Count'}]
- AllowDecisions [TargetResource=rot-spendcap-gw-e0umswk6ss, OperationName=AuthorizeAction, PolicyEngine=rot_spendcap_engine-rzhlj_2hg9]: [{'Timestamp': '2026-11-05T02:18:00+00:00', 'SampleCount': 3.0, 'Sum': 3.0, 'Unit': 'Count'}]
- AllowDecisions [OperationName=AuthorizeAction, PolicyEngine=rot_spendcap_engine-rzhlj_2hg9]: [{'Timestamp': '2026-11-05T02:18:00+00:00', 'SampleCount': 3.0, 'Sum': 3.0, 'Unit': 'Count'}]
- AllowDecisions [OperationName=AuthorizeAction, Mode=ENFORCE, PolicyEngine=rot_spendcap_engine-rzhlj_2hg9]: [{'Timestamp': '2026-11-05T02:18:00+00:00', 'SampleCount': 3.0, 'Sum': 3.0, 'Unit': 'Count'}]
- AllowDecisions [TargetResource=rot-spendcap-gw-e0umswk6ss, OperationName=AuthorizeAction, Mode=ENFORCE]: [{'Timestamp': '2026-11-05T02:18:00+00:00', 'SampleCount': 3.0, 'Sum': 3.0, 'Unit': 'Count'}]
- TemporalLatency [TargetResource=rot-spendcap-gw-e0umswk6ss, OperationName=AuthorizeAction]: [{'Timestamp': '2026-11-05T02:18:00+00:00', 'SampleCount': 3.0, 'Sum': 77.0, 'Unit': 'Milliseconds'}]
- SystemErrors [Resource=arn:aws:bedrock-agentcore:us-east-1:626756230713:gateway/rot-spendcap-gw-e0umswk6ss, Operation=InvokeGateway, Method=tools/call, Protocol=MCP]: [{'Timestamp': '2026-11-05T02:18:00+00:00', 'SampleCount': 3.0, 'Sum': 0.0, 'Unit': 'Count'}]

## Gateway responses (truncated)
### fire-1.json

```
{"jsonrpc":"2.0","id":1,"result":{"isError":false,"content":[{"type":"text","text":"{\"txId\":\"rot-1e0ff80a5e18\",\"amount\":100,\"status\":\"SETTLED\",\"currency\":\"USD\",\"mock\":true}"}]}}
```

### fire-2.json

```
{"jsonrpc":"2.0","id":2,"result":{"isError":false,"content":[{"type":"text","text":"{\"txId\":\"rot-306def820a18\",\"amount\":100,\"status\":\"SETTLED\",\"currency\":\"USD\",\"mock\":true}"}]}}
```

### fire-3.json

```
{"jsonrpc":"2.0","id":3,"result":{"isError":false,"content":[{"type":"text","text":"{\"txId\":\"rot-21c39914a00c\",\"amount\":100,\"status\":\"SETTLED\",\"currency\":\"USD\",\"mock\":true}"}]}}
```

### fire-results.json

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
```

