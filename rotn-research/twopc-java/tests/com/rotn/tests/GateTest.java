package com.rot.n.tests;

import static org.junit.Assert.*;

import com.rot.n.scheduler.Gate;
import com.rot.n.scheduler.GateException;
import com.rot.n.scheduler.ScheduleReader;

import org.junit.After;
import org.junit.Test;

import java.util.List;

/** W5 — scheduler gate: the W3 replay entry point.
 *
 *  The gate is a synchronous step-matcher: a spec site consumes the next
 *  expected (owner, action) or the replay aborts. When no gate is active it
 *  is a no-op, leaving the W1/W2 free-run path untouched.
 */
public class GateTest {

    @After
    public void tearDown() {
        Gate.deactivate();
    }

    private List<ScheduleReader.Step> steps(String... oa) {
        return Sched.steps(oa);
    }

    @Test
    public void inactive_gate_is_noop() {
        // No active gate -> spec sites are unaffected (free-run W1/W2 path).
        Gate.check("coordinator", "decide");
        Gate.check("participant_1", "vote_1_yes");
        assertNull(Gate.active);
    }

    @Test
    public void matching_check_consumes_step() {
        Gate g = new Gate(steps("coordinator", "decide"));
        Gate.activate(g);
        Gate.check("coordinator", "decide");
        assertTrue(g.exhausted());
        assertNull(g.peek());
    }

    @Test(expected = GateException.class)
    public void owner_mismatch_throws() {
        Gate.activate(new Gate(steps("coordinator", "decide")));
        Gate.check("participant_1", "decide");   // wrong owner -> GateException
    }

    @Test(expected = GateException.class)
    public void action_mismatch_throws() {
        Gate.activate(new Gate(steps("coordinator", "decide")));
        Gate.check("coordinator", "vote");       // wrong action -> GateException
    }

    @Test(expected = GateException.class)
    public void exhausted_schedule_throws() {
        Gate g = new Gate(steps("coordinator", "decide"));
        Gate.activate(g);
        Gate.check("coordinator", "decide");          // consumes the only step
        Gate.check("participant_1", "vote_1_yes");    // now exhausted -> throws
    }

    @Test
    public void peek_does_not_consume() {
        Gate g = new Gate(steps("coordinator", "decide", "participant_1", "apply_1"));
        assertNotNull(g.peek());
        assertNotNull(g.peek());   // repeat peek, still not consumed
        assertFalse(g.exhausted());
    }

    @Test
    public void multiple_steps_consume_in_order() {
        Gate g = new Gate(steps(
                "participant_1", "vote_1_yes",
                "participant_2", "vote_2_no",
                "coordinator", "decide"));
        Gate.activate(g);
        Gate.check("participant_1", "vote_1_yes");
        Gate.check("participant_2", "vote_2_no");
        Gate.check("coordinator", "decide");
        assertTrue(g.exhausted());
    }

    @Test
    public void deactivate_restores_noop() {
        Gate.activate(new Gate(steps("coordinator", "decide")));
        Gate.deactivate();
        assertNull(Gate.active);
        Gate.check("coordinator", "decide");   // no-op now, no exception
    }
}