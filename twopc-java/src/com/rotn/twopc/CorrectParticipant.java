package com.rot.n.twopc;

/** Correct 2PC participant -- mirrors twopc_correct in rot/twopc.py:
 *  votes from its own state and applies the coordinator's decision
 *  (applied_i = decision). Agreement holds by construction.
 *
 *  voteDelayMs models a slow participant (environment timing only; the
 *  model captures the same scenario with the participant voting late).
 */
public class CorrectParticipant extends Participant {
    private final long voteDelayMs;

    public CorrectParticipant(int index, Bus bus, boolean canCommit, long voteDelayMs) {
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
                } else if (m.type == Message.Type.DECISION) {
                    replayApply(m);
                    return;
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** Apply the coordinator's decision (applied_i = decision). The SPEC
     *  event is recorded *before* the applied state is published, so once
     *  applied() is non-null the trace is guaranteed to contain apply_<i>. */
    @Override
    public void replayApply(Message decision) {
        spec("apply_" + index, "applied_" + index + "=" + decision.value);
        apply(decision.value);
    }
}
