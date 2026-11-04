# rotn:shape=approval_replay
# rotn:variant=buggy
package rotn.apw2

# AI-authored policy -- the canonical Rego encoding of APW-2 (approval
# replay), BUGGY variant.  Intent: "an order is permitted only after the
# cart has been checked."
#
# The natural first draft treats the cart check as a *bare* temporal fact:
# once observed it stays true, so ONE cart check admits EVERY later order
# (the APW-2 replay).  In Dogwood this is the missing `since` clause
# (samples/apw2-buggy.dw).  The stub front-end (rot.frontends.policy.opa)
# lowers on the `# rotn:` annotations; the rule bodies are the
# human/AI-readable draft.

# the approval: a cart check was observed (a bare, sticky fact)
approval {
    observed_event == "get_cart::response"
}

# the gated action: place an order while the approval fact holds.
# BUGGY: nothing consumes the approval -- it can fire again and again.
allow {
    action == "place_order"
    approval
}