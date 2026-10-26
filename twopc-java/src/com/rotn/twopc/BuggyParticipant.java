package com.rot.n.twopc;

/** Buggy 2PC participant -- the seeded bug (mirrors twopc_buggy in
 *  rot/twopc.py): after voting, the participant decides and applies from
 *  its OWN vote (applied_i = vote_i), ignoring the coordinator's decision.
 *
 *  With a mixed vote set this breaks agreement: the "yes" participant
 *  self-commits while the "no" participant self-aborts.
 *
 *  Note the race: the self-apply happens as soon as the participant has
 *  voted, typically BEFORE the coordinator's decision is broadcast. The
 *  trace checker (W4) therefore has two independent ways to flag this
 *  run: (a) apply_<i> occurs while the model phase is still "prepare"
 *  (guard violation), and (b) the final applied values disagree
 *  (agreement invariant violation).
 */
public class BuggyParticipant extends Participant {
    private final long voteDelayMs;

    public BuggyParticipant(int index, Bus bus, boolean canCommit, long voteDelayMs) {
        super(index, bus, canCommit);
        this.voteDelayMs = voteDelayMs;
    }

    @Override
    public void run() {
        try {
            while (true) {
                Message m = bus.recv(50);
                if (m == null) {
                    continue;
                }
                if (m.type == Message.Type.ASK) {
                    if (voteDelayMs > 0) {
                        Thread.sleep(voteDelayMs);
                    }
                    replayVote();
                    // BUG: self-decides from its own vote, ignoring the coordinator
                    String self = "yes".equals(lastVote) ? "commit" : "abort";
                    spec("apply_" + index, "applied_" + index + "=" + self + " (self-decided)");
                    apply(self);
                }
                // DECISION messages are ignored: the participant already applied.
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** W3 replay: the gate defers apply_<i> until after the coordinator's
     *  decide, but the bug is preserved -- the participant applies its OWN
     *  vote value, not the coordinator's decision. */
    @Override
    public void replayApply(Message decision) {
        String self = "yes".equals(lastVote) ? "commit" : "abort";
        spec("apply_" + index, "applied_" + index + "=" + self + " (self-decided)");
        apply(self);
    }
}
