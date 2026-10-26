package com.rot.n.twopc;

import com.rot.n.scheduler.Gate;

/** Base class for a 2PC participant thread.
 *
 *  Thread name == model owner id ("participant_<i>"), so the W3 scheduler
 *  can gate per owner. Protocol state:
 *
 *    canCommit -- this participant's own vote (yes iff canCommit)
 *    applied   -- the decision this participant finally applied (null until applied)
 */
public abstract class Participant extends Thread {
    protected final String id;          // "participant_<i>"
    protected final int index;
    protected final Bus bus;
    private final boolean canCommit;
    private String applied;             // null | "commit" | "abort"
    protected final Object stateLock = new Object();
    protected String lastVote;          // this participant's last cast vote (replay)

    protected Participant(int index, Bus bus, boolean canCommit) {
        super(Names.PART + index);
        this.index = index;
        this.id = Names.PART + index;
        this.bus = bus;
        this.canCommit = canCommit;
        setDaemon(true);
    }

    public final String id() {
        return id;
    }

    protected final boolean canCommitNow() {
        synchronized (stateLock) {
            return canCommit;
        }
    }

    protected final void apply(String decision) {
        synchronized (stateLock) {
            applied = decision;
        }
    }

    public final String applied() {
        synchronized (stateLock) {
            return applied;
        }
    }

    /** W3 replay: cast the vote (gate-checked spec record + wire message).
     *  Called by the single-threaded replay driver instead of run(). */
    public final void replayVote() throws InterruptedException {
        String vote = canCommitNow() ? "yes" : "no";
        lastVote = vote;
        spec("vote_" + index + "_" + vote, "vote_" + index + "=" + vote);
        bus.send(new Message(Message.Type.VOTE, id, Names.COORD, vote));
    }

    /** W3 replay: react to the coordinator's DECISION message. A correct
     *  participant applies the decision; the buggy participant applies its
     *  own vote (the seeded bug, now deferred past the coordinator's decide). */
    public abstract void replayApply(Message decision) throws InterruptedException;

    /** Record a spec event (model action) for this participant. When a W3
     *  replay gate is active the (owner, action) pair is checked against the
     *  expected schedule step first; with no gate active this is a plain
     *  spec record (the free-run W1/W2 path). */
    protected final void spec(String action, String payload) {
        Gate.check(id, action);
        bus.record(TraceEvent.spec(id, action, payload));
    }
}
