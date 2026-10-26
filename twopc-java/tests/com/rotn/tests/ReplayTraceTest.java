package com.rot.n.tests;

import static org.junit.Assert.*;

import com.rot.n.scheduler.Gate;
import com.rot.n.scheduler.ScheduleReader;
import com.rot.n.twopc.Bus;
import com.rot.n.twopc.Coordinator;
import com.rot.n.twopc.CorrectParticipant;
import com.rot.n.twopc.Message;
import com.rot.n.twopc.Names;
import com.rot.n.twopc.Participant;
import com.rot.n.twopc.TraceEvent;

import org.junit.After;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

/**
 * W5 — replay-path trace validity.
 *
 * A gate-gated, single-threaded replay of the W3 witness schedule emits a
 * structurally valid trace: every event carries a non-null owner (actor) and
 * a non-empty action, and the total-order seq is strictly increasing (the
 * single Bus.record() choke point assigns it). This is the Java-side
 * counterpart of the W1/W3 trace contract the Python suites assert over the
 * generated replay artifacts.
 *
 * Read-only: the gate constrains scheduling; nothing is refined.
 */
public final class ReplayTraceTest {

    @After
    public void tearDown() {
        Gate.deactivate();
    }

    @Test
    public void gatedReplayEmitsStrictlyOrderedTrace() throws Exception {
        Bus bus = new Bus(Names.COORD, "participant_1", "participant_2");
        Coordinator coord = new Coordinator(bus, Arrays.asList(1, 2), 100L);
        Participant p1 = new CorrectParticipant(1, bus, true, 0L);
        Participant p2 = new CorrectParticipant(2, bus, false, 0L);

        // The W3 witness schedule (vote, vote, decide, apply, apply).
        List<ScheduleReader.Step> steps = Sched.steps(
                "participant_1", "vote_1_yes",
                "participant_2", "vote_2_no",
                "coordinator", "decide",
                "participant_1", "apply_1",
                "participant_2", "apply_2");
        Gate.activate(new Gate(steps));
        try {
            p1.replayVote();
            p2.replayVote();
            assertEquals("abort", coord.replayDecide());
            p1.replayApply(new Message(Message.Type.DECISION, Names.COORD, p1.id(), "abort"));
            p2.replayApply(new Message(Message.Type.DECISION, Names.COORD, p2.id(), "abort"));
        } finally {
            Gate.deactivate();
        }

        List<TraceEvent> ev = bus.events();
        assertFalse("expected trace events", ev.isEmpty());

        // Structural validity: owner + action on every event, strictly
        // increasing total order (seq), and the full SPEC sequence present.
        long prev = -1L;
        int spec = 0;
        boolean hasVote = false, hasDecide = false, hasApply = false;
        for (TraceEvent e : ev) {
            assertNotNull("event missing owner (actor)", e.actor);
            assertFalse("owner should be non-empty", e.actor.isEmpty());
            assertNotNull("event missing action", e.action);
            assertFalse("action should be non-empty", e.action.isEmpty());
            assertTrue("seq must be strictly increasing: " + prev + " !< " + e.seq, e.seq > prev);
            prev = e.seq;
            if (e.kind == TraceEvent.Kind.SPEC) {
                spec++;
                if (e.action.contains("vote")) { hasVote = true; }
                if ("decide".equals(e.action)) { hasDecide = true; }
                if (e.action.contains("apply")) { hasApply = true; }
            }
        }
        assertTrue("expected SPEC vote events", hasVote);
        assertTrue("expected a SPEC decide event", hasDecide);
        assertTrue("expected SPEC apply events", hasApply);
        assertEquals("expected 5 SPEC events (2 vote + 1 decide + 2 apply)", 5, spec);
    }
}