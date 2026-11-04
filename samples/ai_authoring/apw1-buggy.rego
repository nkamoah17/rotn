# rotn:shape=spendcap
# rotn:variant=buggy
# rotn:amount=100
# rotn:cap=200
package rotn.apw1

# AI-authored policy -- the canonical Rego encoding of APW-1 (settled-sum
# cap bypass), BUGGY variant.  Intent: "spend up to $200."
#
# The natural first draft charges only *settled* (responded) requests
# against the cap -- the in-flight set is invisible, so a parallel burst
# of $100 fires each passes the per-request check and commits $300
# against the $200 cap.  In Dogwood: summing the ::response events
# (samples/apw1-buggy.dw).

allow {
    action == "spend"
    input.amount == 100
    # BUGGY: settled responses only -- in-flight requests are invisible
    input.settled + input.amount <= 200
}