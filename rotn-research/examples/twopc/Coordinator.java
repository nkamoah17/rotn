package twopc;

import java.util.ArrayList;
import java.util.List;

/**
 * Two-phase-commit coordinator (synchronous reference model).
 *
 * This is a faithful *synchronous* reference of the 2PC coordinator, written so
 * that a per-method model extraction (rot.frontends.java) yields the intended
 * actions:
 *
 *   prepare()  -> send prepare to every participant
 *   decide()   -> if all participants voted YES: decision = COMMIT else ABORT,
 *                 then phase = DECIDED
 *   apply(i)   -> applied[i] = decision            (CORRECT: uses the
 *                                                coordinator's decision)
 *   commit()   -> send commit to every participant
 *   abort()    -> send abort  to every participant
 *
 * The decision is made ONCE (decide()), broadcast (commit/abort), and applied
 * per participant (apply()).  All participants therefore observe the SAME
 * decision -> the agreement invariant holds.
 *
 * NOTE: apply() reads the SHARED decision field.  A buggy implementation that
 * instead recomputes each participant's decision from that participant's local
 * vote (as in the twopc.Probe class) reintroduces disagreement -- that is the
 * bug rot.frontends.java must flag in --buggy mode.
 */
public class Coordinator {

    public final int n;                       // number of participants
    public final List<Participant> ps;        // participants 1..n

    public Phase phase = Phase.PREPARE;       // coordinator phase
    public Decision decision = Decision.NONE; // the single decision
    public final boolean[] yes;               // yes[i-1] == participant i voted YES

    public Coordinator(List<Participant> ps) {
        this.ps = ps;
        this.n = ps.size();
        this.yes = new boolean[n];
    }

    /** Action: prepare. Sends prepare to every participant. */
    public void prepare() {
        for (int i = 0; i < n; i++) ps.get(i).prepare();
    }

    /** Action: vote. Participant i records its vote (YES in the correct run). */
    public void vote(int i) {
        ps.get(i - 1).voteYes();
        yes[i - 1] = ps.get(i - 1).vote == Vote.YES;
    }

    /**
     * Action: decide. Makes the single decision from all votes, then DECIDED.
     *
     *   if all(vote[i] == YES)  decision = COMMIT
     *   else                    decision = ABORT
     *   phase = DECIDED
     */
    public void decide() {
        boolean allYes = true;
        for (int i = 0; i < n; i++) allYes = allYes && yes[i];
        decision = allYes ? Decision.COMMIT : Decision.ABORT;
        phase = Phase.DECIDED;
    }

    /**
     * Action: apply(i). Applies the (single) decision to participant i.
     * CORRECT: reads the shared decision, so every participant gets the same one.
     */
    public void apply(int i) {
        ps.get(i - 1).applied = decision;
    }

    /** Action: commit. Broadcasts commit to every participant (linearization). */
    public void commit() {
        for (int i = 0; i < n; i++) ps.get(i).applyCommit();
    }

    /** Action: abort. Broadcasts abort to every participant (linearization). */
    public void abort() {
        for (int i = 0; i < n; i++) ps.get(i).applyAbort();
    }
}
