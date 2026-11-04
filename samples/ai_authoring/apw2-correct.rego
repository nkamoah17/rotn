# rotn:shape=approval_replay
# rotn:variant=correct
package rotn.apw2

# AI-authored policy -- the canonical Rego encoding of APW-2 (approval
# replay), CORRECT variant.  Intent: "an order is permitted only after the
# cart has been checked, and ONE cart check authorises exactly ONE order."
#
# The load-bearing clause is the single-use binding: an order is admitted
# only since the cart check AND no order has already been placed since
# that check.  In Dogwood this is the `since` clause
# (samples/apw2-correct.dw).

# the approval: a cart check was observed and has NOT been consumed
approval {
    observed_event == "get_cart::response"
    not order_placed_since_check
}

# the gated action: place an order (placing it consumes the approval)
allow {
    action == "place_order"
    approval
}