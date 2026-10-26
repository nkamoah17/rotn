package com.rot.n.twopc;

/** One trace event.
 *
 *  SPEC events carry the model action name ("vote_1_yes", "decide",
 *  "apply_2") and a compact payload naming the model variable they
 *  observe/set ("vote_1=yes"). TRANSPORT events (SEND/RECV) are
 *  environment detail kept for auditability; the trace checker (W4)
 *  reasons only about SPEC events.
 *
 *  seq is assigned by Bus.record() and gives the global total order
 *  (the lock-sequence ordering required by the Phase 2 plan).
 */
public final class TraceEvent {
    public enum Kind { SEND, RECV, SPEC }

    public final String actor;    // model owner ("coordinator", "participant_1")
    public final String thread;   // OS thread name (== actor for protocol threads)
    public final Kind kind;
    public final String action;   // model action name for SPEC; transport label otherwise
    public final String payload;  // compact description, e.g. "vote_1=yes"
    public long seq;              // total order; assigned by Bus.record()

    TraceEvent(String actor, Kind kind, String action, String payload) {
        this.actor = actor;
        this.thread = Thread.currentThread().getName();
        this.kind = kind;
        this.action = action;
        this.payload = payload;
        this.seq = -1L;
    }

    static TraceEvent spec(String actor, String action, String payload) {
        return new TraceEvent(actor, Kind.SPEC, action, payload);
    }

    static TraceEvent transport(Kind kind, String actor, String action, String payload) {
        return new TraceEvent(actor, kind, action, payload);
    }

    public String describe() {
        return String.format("%d|%s|%s|%s|%s", seq, thread, kind, action, payload);
    }
}
