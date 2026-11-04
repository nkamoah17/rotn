# rotn:shape=spendcap
# rotn:variant=correct
# rotn:amount=100
# rotn:cap=200
package rotn.apw1

# AI-authored policy -- the canonical Rego encoding of APW-1 (settled-sum
# cap bypass), CORRECT variant.  Intent: "spend up to $200."
#
# The fix: charge the in-flight set against the cap too -- settled amount,
# plus the amount already in flight, plus this request, must all fit
# within the cap.  In Dogwood: summing the ::request events
# (samples/apw1-correct.dw).

allow {
    action == "spend"
    input.amount == 100
    # CORRECT: settled + in-flight + this request all fit within the cap
    input.settled + input.inflight * 100 + input.amount <= 200
}