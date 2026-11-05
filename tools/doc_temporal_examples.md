

# Temporal policy examples
<a name="example-policies-temporal"></a>

The policies in this section decide from what has already happened earlier in the same session. They let you require an approval before a payout, expire a permission that has gone stale, cap a running total, or block an action after a failure. No single request carries enough information to decide any of these.

Every example authorizes the reference gateway described in [Resource configuration for examples](example-policies-reference.md). For the temporal event schema, the operators, session IDs, quotas, and Region availability, see [Temporal policies](policy-temporal.md) and [Authoring temporal policies](policy-temporal-authoring.md).

## Before you use these examples
<a name="example-policies-temporal-before"></a>

Four things determine whether a temporal policy behaves the way you expect.

 **A session ID is required**   
Temporal history is scoped to a session that you name. Send a session ID in the `x-amzn-bedrock-agentcore-policy-session-id` header on every request, starting with the first. The gateway does not generate one for you, and if the engine holds a temporal policy, a request with no session ID fails validation.

 **Only permitted actions become `response` events**   
An action records a `response` event only if a policy permitted it and it completed. A denied action records an `error` event instead. So each of the following examples needs a plain `permit` for the prerequisite action as well — otherwise the prerequisite is denied, never recorded as a `response`, and the temporal condition can never match. Every example states which permits to pair it with.

 ** `eventResource: resource` is mandatory**   
Every predicate must include `eventResource: resource`, which ties the matched event to the resource in the policy’s scope. Omitting it is rejected with `temporal predicates do not constrain the matched event to the current request’s resource`. You do not need to write `sessionId` — the event schema scopes every predicate to the current session already.

 **Ordered comparisons need integers; equality does not**   
Inside a `temporal { }` block the two kinds of comparison accept different types.  
+  **Ordering** — `<`, `⇐`, `>`, `>=` — requires an `integer` on both sides. A `decimal` or a `string` is rejected when you create the policy, with `comparison requires numeric operands on both sides`.
+  **Equality** — `==` and `!=` — works on any type, as long as both sides are the same type. This is what correlation uses: matching `input.claimId` against `context.input.claimId` compares two strings, which is supported.
So model any value a temporal policy has to **total or threshold** as an `integer`. This is why the reference gateway states money in integer minor units on the tools these examples aggregate. Summing has the same requirement and its own message: `sum` needs an `integer` summand. For more information, see [Parameter types in conditions](example-policies-reference.md#example-policies-types).

## Require a prior approval for the same claim
<a name="example-policies-temporal-integrity"></a>

 **Intent:** Allow a payment to be disbursed only for a claim that was approved earlier in the session, so the agent cannot disburse against a claim ID it invented.

The `::response` predicate matches a completed `approve_claim`. Correlating its `output.claimId` with the current request’s `context.input.claimId` is what ties the disbursement to that specific approval — without the correlation, any approval in the session would authorize a payout on any claim.

```
permit (
    principal,
    action == AgentCore::Action::"InsuranceAPI___disburse_payment",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/insurance-gw-a1b2c3d4e5"
)
when temporal {
    formerly within 1h AgentCore::Action::"InsuranceAPI___approve_claim"::response{
        eventResource: resource,
        output.claimId: context.input.claimId
    }
};
```

**Important**  
 `output.*` fields exist on a `response` event only when the target declares an output schema for the tool. Many targets do not — a Lambda target, for instance, commonly declares inputs only, and then the event carries just `eventPrincipal`, `eventResource`, `input.*`, `requestId`, and `sessionId`.  
If you name a field the event does not declare, the service rejects the policy and the error lists what **is** available:  

```
predicate `AgentCore::Action::"MyTarget___verify_purchase"::response` mentions field
`output.orderId`, which is not declared on that event (declared fields: eventPrincipal,
eventResource, input.orderId, requestId, sessionId)
```
Use that list to see what you can correlate on. Where no output field exists, correlate on a shared **input** field — `input.claimId: context.input.claimId` ties the two calls to the same claim without needing the prior tool to return anything.  
The two are not equivalent, so choose deliberately. An input correlation matches what the earlier call **requested**; an output correlation matches what it **returned**. If your rule depends on a value the prior tool produced — an approval ID, a computed amount — only an output correlation enforces it, and that requires the target to declare an output schema.

Pair this with a plain permit so approvals are allowed and recorded:

```
permit (
    principal,
    action == AgentCore::Action::"InsuranceAPI___approve_claim",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/insurance-gw-a1b2c3d4e5"
);
```


| Request sequence in a session | Decision | 
| --- | --- | 
|  `disburse_payment` with no prior approval | DENY | 
|  `approve_claim` for a claim, then `disburse_payment` for the same claim | ALLOW | 
|  `approve_claim` for one claim, then `disburse_payment` for a different claim | DENY | 

## Require a prerequisite action
<a name="example-policies-temporal-sequencing"></a>

 **Intent:** Allow a claim to be approved only after someone looked up its status in the session.

Matching `::request` means the prerequisite only has to have been **attempted**, not to have succeeded. Pair with a permit for `get_claim_status`.

```
permit (
    principal,
    action == AgentCore::Action::"InsuranceAPI___approve_claim",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/insurance-gw-a1b2c3d4e5"
)
when temporal {
    formerly within 5m AgentCore::Action::"InsuranceAPI___get_claim_status"::request{
        eventResource: resource
    }
};
```

## Require a **successful** prerequisite, recently
<a name="example-policies-temporal-freshness"></a>

 **Intent:** Allow approval only if a status lookup **completed** in the last five minutes, so a stale lookup stops conferring permission.

The only change from the previous example is `::response` in place of `::request`, and it is the difference between "was attempted" and "succeeded". The window length sets how fresh that success must be; once it passes, the permission lapses until the prerequisite runs again.

```
permit (
    principal,
    action == AgentCore::Action::"InsuranceAPI___approve_claim",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/insurance-gw-a1b2c3d4e5"
)
when temporal {
    formerly within 5m AgentCore::Action::"InsuranceAPI___get_claim_status"::response{
        eventResource: resource
    }
};
```


| Request sequence in a session | Decision | 
| --- | --- | 
|  `approve_claim` before any completed lookup | DENY | 
| lookup completes, then `approve_claim` within the window | ALLOW | 
|  `approve_claim` after the window elapses | DENY | 

## Cap how many times an action runs
<a name="example-policies-temporal-rate-limit"></a>

 **Intent:** Allow at most three disbursements in any five-minute stretch of a session.

 `count` counts the matching events in the window, including the request being authorized, so the fourth call in a window is the first to be denied. The `exists (n: Long)` binder captures the count so the `n > 3` filter can test it; the aggregate needs parentheses on the left of `==`. Pair with a permit for `disburse_payment` so calls are allowed up to the limit.

```
forbid (
    principal,
    action == AgentCore::Action::"InsuranceAPI___disburse_payment",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/insurance-gw-a1b2c3d4e5"
)
when temporal {
    exists (n: Long).
        (count for (t: Timepoint).
            where (formerly within 5m (AgentCore::Action::"InsuranceAPI___disburse_payment"::request{ eventResource: resource } && tp(t)))) == n
        && n > 3
};
```

**Important**  
This is not a security control. The caller supplies the session ID, so they can reset the count by starting a new session. Use it to shape behavior inside a cooperative session — to stop a looping agent, for example — not to enforce a limit against a caller who controls their own session ID. For more information, see [Security considerations](policy-temporal.md#policy-temporal-security).

## Cap a running total
<a name="example-policies-temporal-budget"></a>

 **Intent:** Allow disbursements until they total 3,000.00 within five minutes, then stop.

 `sum` adds the named input field across the matching events, including the current request, so a request that would cross the threshold is the one denied. With a 300000-cent cap and disbursements of 100000, the first two are allowed and the third is denied.

```
forbid (
    principal,
    action == AgentCore::Action::"InsuranceAPI___disburse_payment",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/insurance-gw-a1b2c3d4e5"
)
when temporal {
    exists (total: Long).
        (sum amt for (amt: Long), (t: Timepoint).
            where (formerly within 5m (AgentCore::Action::"InsuranceAPI___disburse_payment"::request{ eventResource: resource, input.amountCents: amt } && tp(t)))) == total
        && total >= 300000
};
```

The two-variable domain, `for (amt: Long), (t: Timepoint)`, is required: `amt` is the value being summed and `t` distinguishes the timepoints, so two disbursements of the same amount are counted twice rather than deduplicated into one.

**Note**  
 `amountCents` is an `integer` in the tool schema, and that is what makes this policy work. The `sum` aggregation needs an integer summand, and the ordering comparison on `total` needs an integer on both sides, so a field your schema declares as a `number` cannot drive a cap like this one. For the type rules these examples depend on, see [Before you use these examples](#example-policies-temporal-before).

## Make each approval good for one use
<a name="example-policies-temporal-one-time"></a>

 **Intent:** Allow one disbursement per approval. After a payout, require a fresh approval.

The `since` operator holds when the anchor on its right occurred within the window and the condition on its left held continuously since then. Here that reads: an approval completed within the last hour, and no disbursement has completed since it. The first payout after an approval consumes it.

```
permit (
    principal,
    action == AgentCore::Action::"InsuranceAPI___disburse_payment",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/insurance-gw-a1b2c3d4e5"
)
when temporal {
    !AgentCore::Action::"InsuranceAPI___disburse_payment"::response{ eventResource: resource }
    since within 1h AgentCore::Action::"InsuranceAPI___approve_claim"::response{ eventResource: resource }
};
```

Matching `::response` on the negated side is essential. The request being authorized has not produced a response yet, so it does not block itself — matching `::request` there would make every disbursement deny itself.


| Request sequence in a session | Decision | 
| --- | --- | 
|  `approve_claim`, then `disburse_payment`  | ALLOW | 
| a second `disburse_payment` with no new approval | DENY | 
| a new `approve_claim`, then `disburse_payment`  | ALLOW | 

**Note**  
A `response` event is recorded shortly after the call completes. Wait for the approval to return before issuing the disbursement rather than sending them back to back. For more information, see [Sequencing actions that depend on a prior response](policy-temporal.md#policy-temporal-response-delay).

## Enforce a cool-down
<a name="example-policies-temporal-cooldown"></a>

 **Intent:** Prevent the same action from repeating within a minute of completing.

This condition refers to the same action it authorizes. `::response` is what makes that safe: the current request has no response yet, so it does not match itself. Written with `::request`, the current request would match its own event and the action would be forbidden permanently. For more information, see [Self-referential conditions include the current request](policy-temporal.md#policy-temporal-self-referential).

```
forbid (
    principal,
    action == AgentCore::Action::"InsuranceAPI___disburse_payment",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/insurance-gw-a1b2c3d4e5"
)
when temporal {
    formerly within 1m AgentCore::Action::"InsuranceAPI___disburse_payment"::response{
        eventResource: resource
    }
};
```

## Require a precondition that has not been invalidated
<a name="example-policies-temporal-precondition"></a>

 **Intent:** Allow disbursement while an approval stands, and withdraw permission if the claim is reopened for status review afterward.

This has the same shape as the one-time-use approval, but the negated action differs from the action being authorized, which turns "consume the approval" into "invalidate the approval". Grant permits for both `approve_claim` and `get_claim_status`.

```
permit (
    principal,
    action == AgentCore::Action::"InsuranceAPI___disburse_payment",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/insurance-gw-a1b2c3d4e5"
)
when temporal {
    !AgentCore::Action::"InsuranceAPI___get_claim_status"::response{ eventResource: resource }
    since within 5m AgentCore::Action::"InsuranceAPI___approve_claim"::response{ eventResource: resource }
};
```


| Request sequence in a session | Decision | 
| --- | --- | 
|  `disburse_payment` before any approval | DENY | 
|  `approve_claim`, then `disburse_payment`  | ALLOW | 
|  `get_claim_status` occurs, then `disburse_payment`  | DENY | 
| a new `approve_claim`, then `disburse_payment`  | ALLOW | 

## Require a chain of actions in order
<a name="example-policies-temporal-chain"></a>

 **Intent:** Require the sequence status lookup, then approval, then disbursement.

One policy per link, and the chain emerges from their composition. Grant a plain permit for the first action so the chain can start. A step attempted out of order is denied until its prerequisite completes.

```
// Link 1: approve only after a completed status lookup
permit (
    principal,
    action == AgentCore::Action::"InsuranceAPI___approve_claim",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/insurance-gw-a1b2c3d4e5"
)
when temporal {
    formerly within 5m AgentCore::Action::"InsuranceAPI___get_claim_status"::response{ eventResource: resource }
};

// Link 2: disburse only after a completed approval
permit (
    principal,
    action == AgentCore::Action::"InsuranceAPI___disburse_payment",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/insurance-gw-a1b2c3d4e5"
)
when temporal {
    formerly within 5m AgentCore::Action::"InsuranceAPI___approve_claim"::response{ eventResource: resource }
};
```

## Require two prerequisites in any order
<a name="example-policies-temporal-parallel"></a>

 **Intent:** Allow disbursement only after both a status lookup and an approval have completed, in either order.

Two `formerly` conditions joined with `&&` require both, and neither constrains the order. This uses two of the three temporal operators a single policy may contain.

```
permit (
    principal,
    action == AgentCore::Action::"InsuranceAPI___disburse_payment",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/insurance-gw-a1b2c3d4e5"
)
when temporal {
    formerly within 1h AgentCore::Action::"InsuranceAPI___get_claim_status"::response{ eventResource: resource }
    && formerly within 1h AgentCore::Action::"InsuranceAPI___approve_claim"::response{ eventResource: resource }
};
```

## Make two actions mutually exclusive
<a name="example-policies-temporal-mutex"></a>

 **Intent:** Within two minutes, allow either a disbursement or a deletion of a claim, but not both.

Exclusion needs two symmetric policies, one per direction; a single `forbid` would only block one order. Matching `::request` means merely **attempting** one action blocks the other, without waiting for it to complete.

```
// Forbid deletion if a disbursement was requested within 2m
forbid (
    principal,
    action == AgentCore::Action::"InsuranceAPI___delete_claim",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/insurance-gw-a1b2c3d4e5"
)
when temporal {
    formerly within 2m AgentCore::Action::"InsuranceAPI___disburse_payment"::request{ eventResource: resource }
};

// Forbid disbursement if a deletion was requested within 2m
forbid (
    principal,
    action == AgentCore::Action::"InsuranceAPI___disburse_payment",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/insurance-gw-a1b2c3d4e5"
)
when temporal {
    formerly within 2m AgentCore::Action::"InsuranceAPI___delete_claim"::request{ eventResource: resource }
};
```

## Require a threshold number of events
<a name="example-policies-temporal-threshold"></a>

 **Intent:** Allow a claim to be deleted only after at least two disbursements completed against it.

Correlating `input.claimId` with the current request’s claim scopes the count to that claim rather than counting every disbursement in the session.

```
permit (
    principal,
    action == AgentCore::Action::"InsuranceAPI___delete_claim",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/insurance-gw-a1b2c3d4e5"
)
when temporal {
    exists (n: Long).
        (count for (t: Timepoint).
            where (formerly within 5m (AgentCore::Action::"InsuranceAPI___disburse_payment"::response{ eventResource: resource, input.claimId: context.input.claimId } && tp(t)))) == n
        && n >= 2
};
```

**Note**  
 `count` counts events, not distinct callers. It cannot express "approved by two different people", because nothing stops one principal from producing all the matching events. For multi-party approval, correlate on `eventPrincipal` or enforce distinctness outside policy.

## Block an action after an earlier denial
<a name="example-policies-temporal-after-denial"></a>

 **Intent:** Stop a session from disbursing after any approval attempt in it was denied.

An `error` event records a request that was denied or that failed, so `::error` is how a policy reacts to a prior failure. Pair this with a plain permit for `disburse_payment` so it is allowed under normal conditions.

```
forbid (
    principal,
    action == AgentCore::Action::"InsuranceAPI___disburse_payment",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/insurance-gw-a1b2c3d4e5"
)
when temporal {
    formerly within 3m AgentCore::Action::"InsuranceAPI___approve_claim"::error{
        eventResource: resource
    }
};
```

This is a useful containment pattern: an agent probing for permissions it does not have gets cut off from the sensitive action rather than being allowed to keep trying.

## Combine temporal, guardrail, and request conditions
<a name="example-policies-temporal-mixed"></a>

 **Intent:** Allow a caller to file claims, provided that the session has fewer than three filings in the past 24 hours, the claim description carries no bank details, and the caller is not a restricted role.

All three condition kinds compose in one policy, and every clause must hold for the `permit` to apply. The `temporal` block enforces the cap, the `when` block screens content, and the `unless` block excludes a role. Each is evaluated independently.

```
permit (
    principal is AgentCore::OAuthUser,
    action == AgentCore::Action::"InsuranceAPI___file_claim",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/insurance-gw-a1b2c3d4e5"
)
when temporal {
    exists (n: Long).
        (count for (t: Timepoint).
            where (formerly within 24h (AgentCore::Action::"InsuranceAPI___file_claim"::request{ eventResource: resource } && tp(t)))) == n
        && n <= 3
}
when {
    BedrockGuardrails::SensitiveInformation(["US_BANK_ACCOUNT_NUMBER"], [context.input.description]).count() == 0
}
unless {
    principal.hasTag("role") &&
    principal.getTag("role") == "restricted"
};
```

The guardrail screens `description`, which is the only free-text parameter `file_claim` takes. Point a sensitive-information guardrail at a field that could plausibly carry the data you are screening for. If you point it at an identifier or a number, it has nothing to detect and the clause silently passes. `description` is optional, so a request that omits it gives the guardrail no text and the clause holds.

## What changes when you edit a temporal policy
<a name="example-policies-temporal-invalidation"></a>

Adding or updating a temporal policy on an engine invalidates that engine’s open temporal sessions, because the recorded history no longer matches the rules being applied to it. The next request that reuses an invalidated session fails with HTTP 409 `ConflictException`. Start a new session and retry; the new session begins with empty history and is evaluated against the updated policies.

**Important**  
Plan for this when you roll out a temporal policy change. Clients need to treat a `409` as "start a new session". Any in-flight multi-step workflow restarts rather than resumes.