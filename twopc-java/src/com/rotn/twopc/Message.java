package com.rot.n.twopc;

/** A 2PC control message on the star bus (coordinator <-> participants).
 *
 *  Vocabulary matches the model: votes are "yes"/"no" (VOTE in rot/twopc.py),
 *  decisions are "commit"/"abort" (DECISION).
 */
public final class Message {
    public enum Type { ASK, VOTE, DECISION }

    public final Type type;
    public final String from;  // model owner of the sender
    public final String to;    // model owner of the receiver
    public final String value; // yes|no for VOTE, commit|abort for DECISION, null for ASK

    public Message(Type type, String from, String to, String value) {
        this.type = type;
        this.from = from;
        this.to = to;
        this.value = value;
    }

    public String describe() {
        return type + " from=" + from + " to=" + to
                + (value == null ? "" : " value=" + value);
    }
}
