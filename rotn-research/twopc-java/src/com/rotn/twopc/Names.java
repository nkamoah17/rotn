package com.rot.n.twopc;

/** Owner identifiers shared with the formal model in rot/twopc.py.
 *
 *  The Java side must use exactly these names: the trace checker
 *  (rot/tracecheck.py, W4) maps runtime actors onto model owners
 *  ("coordinator", "participant_<i>") and runtime action names onto
 *  model actions ("vote_<i>_yes|no", "decide", "apply_<i>").
 */
public final class Names {
    public static final String COORD = "coordinator";
    public static final String PART = "participant_";

    private Names() {
    }
}
