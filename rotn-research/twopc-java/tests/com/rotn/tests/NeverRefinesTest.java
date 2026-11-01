package com.rot.n.tests;

import static org.junit.Assert.*;

import com.rot.n.scheduler.Gate;
import com.rot.n.scheduler.ScheduleReader;
import com.rot.n.twopc.BuggyParticipant;
import com.rot.n.twopc.Bus;
import com.rot.n.twopc.Coordinator;
import com.rot.n.twopc.CorrectParticipant;
import com.rot.n.twopc.Message;
import com.rot.n.twopc.Names;
import com.rot.n.twopc.Participant;
import com.rot.n.twopc.TwoPhaseCommit;

import org.junit.After;
import org.junit.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

/** W5 — never-refines: the W3/W4 replay + verdict surface has NO refinement.
 *
 *  Refinement (CEGAR) is a Phase 1 formal-plane concern (Python). The Java
 *  empirical/replay plane must not expose any refinement entry point, and a
 *  gate-gated deterministic replay must complete with the correct decision —
 *  proving the replay path runs without triggering refinement.
 */
public class NeverRefinesTest {

    @After
    public void tearDown() {
        Gate.deactivate();
    }

    private static final Class<?>[] REPLAY_PATH = {
            Gate.class,
            ScheduleReader.class,
            Participant.class,
            Coordinator.class,
            CorrectParticipant.class,
            BuggyParticipant.class,
            Bus.class,
            TwoPhaseCommit.class,
    };

    private static boolean hasRefineMember(Class<?> c) {
        for (Method m : c.getDeclaredMethods()) {
            if (m.getName().toLowerCase().contains("refine")) {
                return true;
            }
        }
        for (Field f : c.getDeclaredFields()) {
            if (f.getName().toLowerCase().contains("refine")) {
                return true;
            }
        }
        return false;
    }

    @Test
    public void replay_path_exposes_no_refinement_entry_point() {
        for (Class<?> c : REPLAY_PATH) {
            assertFalse(c.getName() + " must not expose a refinement member",
                    hasRefineMember(c));
        }
    }

    @Test
    public void replay_path_class_names_reference_no_formal_plane() {
        for (Class<?> c : REPLAY_PATH) {
            String n = c.getName().toLowerCase();
            assertFalse("class name should not reference CEGAR: " + n, n.contains("cegar"));
            assertFalse("class name should not reference abstraction: " + n, n.contains("abstraction"));
            assertFalse("class name should not reference modelfind: " + n, n.contains("modelfind"));
        }
    }

    @Test
    public void deterministic_replay_completes_with_correct_decision() throws Exception {
        // Drive the W3 replay path: gate-gated, single-threaded, deterministic.
        Bus bus = new Bus(Names.COORD, "participant_1", "participant_2");
        Coordinator coord = new Coordinator(bus, Arrays.asList(1, 2), 100L);
        Participant p1 = new CorrectParticipant(1, bus, true, 0L);
        Participant p2 = new CorrectParticipant(2, bus, false, 0L);

        // The exact SPEC sequence the replay path emits (vote, vote, decide, apply, apply).
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
            String decision = coord.replayDecide();
            assertEquals("abort", decision);
            p1.replayApply(new Message(Message.Type.DECISION, Names.COORD, p1.id(), decision));
            p2.replayApply(new Message(Message.Type.DECISION, Names.COORD, p2.id(), decision));
        } finally {
            Gate.deactivate();
        }
        // Both applied the coordinator's abort decision -> agreement holds.
        assertEquals("abort", p1.applied());
        assertEquals("abort", p2.applied());
    }
}