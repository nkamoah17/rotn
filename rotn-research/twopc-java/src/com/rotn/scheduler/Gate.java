package com.rot.n.scheduler;

import java.util.List;

/** Replay gate: single expected (owner, action) pointer over the schedule
 *  steps. Actors call Gate.check(owner, action) right before recording a
 *  spec event; a mismatch (owner or action, or exhausted schedule) throws
 *  GateException and the replay is rejected. Inactive by default so the
 *  free-run (W1/W2) path is untouched.
 */
public final class Gate {

    public static volatile Gate active;

    private final List<ScheduleReader.Step> steps;
    private int next = 0;

    public Gate(List<ScheduleReader.Step> steps) {
        this.steps = steps;
    }

    public static void activate(Gate g) {
        active = g;
    }

    public static void deactivate() {
        active = null;
    }

    /** No-op when no replay is active; otherwise consumes the next step if
     *  it matches (owner, action) and throws GateException otherwise.
     */
    public static void check(String owner, String action) {
        Gate g = active;
        if (g == null) {
            return;
        }
        g.consume(owner, action);
    }

    public synchronized ScheduleReader.Step peek() {
        if (next < steps.size()) {
            return steps.get(next);
        }
        return null;
    }

    public synchronized void consume(String owner, String action) {
        ScheduleReader.Step s = peek();
        if (s == null) {
            throw new GateException("schedule exhausted but " + owner + " performed " + action);
        }
        if (!s.owner.equals(owner) || !s.action.equals(action)) {
            throw new GateException("gate mismatch: schedule says " + s
                    + " but " + owner + " performed " + action);
        }
        next++;
    }

    public synchronized boolean exhausted() {
        return next >= steps.size();
    }
}
