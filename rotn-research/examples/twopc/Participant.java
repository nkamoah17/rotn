package twopc;

/**
 * Two-phase-commit participant (synchronous reference model).
 *
 * State:
 *   phase     PREPARE | DECIDED | DONE
 *   decision  NONE | COMMIT | ABORT      (the participant's applied decision)
 *   vote      NONE | YES | NO            (its prepare vote)
 *   applied   NONE | COMMIT | ABORT      (what it has actually applied)
 *
 * Actions extracted per method:
 *   prepare()    -> phase = PREPARE (ready to vote)
 *   voteYes()    -> if phase==PREPARE && vote==NONE: vote = YES
 *   applyCommit()-> if phase==DECIDED: applied = decision
 *   applyAbort() -> if phase==DECIDED: applied = decision
 *
 * A participant applies whatever decision the COORDINATOR hands it (applied =
 * decision).  It never invents its own decision from its own vote -- that is
 * what the buggy implementation does, and it is the source of the disagreement
 * that rot.frontends.java must flag in --buggy mode.
 */
public class Participant {

    public Phase phase = Phase.PREPARE;
    public Decision decision = Decision.NONE;
    public Vote vote = Vote.NONE;
    public Decision applied = Decision.NONE;

    /** Action: prepare. Become ready to vote. */
    public void prepare() {
        phase = Phase.PREPARE;
    }

    /** Action: vote. Record a YES vote if eligible. */
    public void voteYes() {
        if (phase != Phase.PREPARE) return;
        if (vote != Vote.NONE) return;
        vote = Vote.YES;
    }

    /** Action: applyCommit. Apply the coordinator's decision (COMMIT path). */
    public void applyCommit() {
        if (phase != Phase.DECIDED) return;
        applied = decision;
    }

    /** Action: applyAbort. Apply the coordinator's decision (ABORT path). */
    public void applyAbort() {
        if (phase != Phase.DECIDED) return;
        applied = decision;
    }
}
