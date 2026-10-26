package com.rot.n.tests;

import static org.junit.Assert.*;

import com.rot.n.twopc.TwoPhaseCommit;
import com.rot.n.twopc.TraceEvent;

import org.junit.Test;

import java.util.List;

/** W5 — concurrency: the Phase 1 AGREE invariant, exercised on the real
 *  multi-threaded two-phase-commit model.
 *
 *  correct variant: participants apply the coordinator's decision ->
 *                   agreement holds (both apply the same value).
 *  buggy variant:   participants self-decide on their own vote -> agreement
 *                   is violated (p1 commits, p2 aborts).
 *
 *  These mirror the invariant the Phase 1 formal model proves (cegar).
 */
public class TwoPhaseCommitTest {

    @Test
    public void correct_variant_preserves_agreement() {
        TwoPhaseCommit.Outcome o = TwoPhaseCommit.run("correct", 150L, 50L);
        assertTrue("correct variant must satisfy agreement", o.agreement);
        assertNotNull(o.applied.get(1));
        assertNotNull(o.applied.get(2));
        assertEquals(o.applied.get(1), o.applied.get(2));
    }

    @Test
    public void buggy_variant_violates_agreement() {
        TwoPhaseCommit.Outcome o = TwoPhaseCommit.run("buggy", 150L, 50L);
        assertFalse("buggy variant must violate agreement", o.agreement);
        assertEquals("commit", o.applied.get(1));   // p1 (can commit) self-commits
        assertEquals("abort", o.applied.get(2));     // p2 (cannot) self-aborts
    }

    @Test
    public void decision_is_abort_in_deadline_scenario() {
        TwoPhaseCommit.Outcome o = TwoPhaseCommit.run("correct", 150L, 50L);
        assertEquals("abort", o.decision);
    }

    @Test
    public void trace_has_strict_total_order() {
        TwoPhaseCommit.Outcome o = TwoPhaseCommit.run("correct", 150L, 50L);
        List<TraceEvent> ev = o.trace;
        assertFalse(ev.isEmpty());
        for (int i = 1; i < ev.size(); i++) {
            assertTrue("seq must be strictly increasing: "
                            + ev.get(i - 1).seq + " !< " + ev.get(i).seq,
                    ev.get(i).seq > ev.get(i - 1).seq);
        }
    }

    @Test
    public void trace_contains_spec_events() {
        TwoPhaseCommit.Outcome o = TwoPhaseCommit.run("correct", 150L, 50L);
        boolean hasVote = false, hasDecide = false, hasApply = false;
        for (TraceEvent e : o.trace) {
            if (e.kind == TraceEvent.Kind.SPEC) {
                String a = e.action == null ? "" : e.action;
                if (a.contains("vote")) hasVote = true;
                if ("decide".equals(a)) hasDecide = true;
                if (a.contains("apply")) hasApply = true;
            }
        }
        assertTrue("expected a vote SPEC event", hasVote);
        assertTrue("expected a decide SPEC event", hasDecide);
        assertTrue("expected an apply SPEC event", hasApply);
    }
}