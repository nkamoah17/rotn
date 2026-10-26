package com.rot.n.twopc;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Driver: wires up and runs one 2PC round, then reports the outcome.
 *
 *  variant = "correct" | "buggy"  (mirrors build_ir(buggy=...) in rot/twopc.py)
 *
 *  Scenario: participant_1 can commit (fast), participant_2 cannot (slow).
 *  The coordinator deadline elapses before participant_2 votes, so the
 *  decision is abort.
 *
 *    correct variant -> both apply abort            (agreement holds)
 *    buggy   variant -> p1 self-commits, p2 self-aborts (agreement violated)
 */
public final class TwoPhaseCommit {

    public static final class Outcome {
        public final String variant;
        public final Map<Integer, String> applied; // participant index -> commit|abort|null
        public final String decision;              // coordinator's decision
        public final boolean agreement;            // all applied values equal (and set)
        public final List<TraceEvent> trace;       // total-ordered (by seq)

        Outcome(String variant, Map<Integer, String> applied, String decision,
                boolean agreement, List<TraceEvent> trace) {
            this.variant = variant;
            this.applied = applied;
            this.decision = decision;
            this.agreement = agreement;
            this.trace = trace;
        }
    }

    public static Outcome run(String variant, long coordinatorTimeoutMs, long slowVoteDelayMs) {
        Bus bus = new Bus(Names.COORD, "participant_1", "participant_2");
        List<Integer> indices = new ArrayList<Integer>();
        indices.add(Integer.valueOf(1));
        indices.add(Integer.valueOf(2));

        Coordinator coordinator = new Coordinator(bus, indices, coordinatorTimeoutMs);
        List<Participant> parts = new ArrayList<Participant>();
        parts.add(make(1, variant, bus, true, 10L));
        parts.add(make(2, variant, bus, false, slowVoteDelayMs));

        coordinator.start();
        for (Participant p : parts) {
            p.start();
        }
        long joinMs = coordinatorTimeoutMs + slowVoteDelayMs + 400L;
        try {
            coordinator.join(joinMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        // Buggy participants intentionally never exit (they keep waiting on the
        // bus after self-applying), so do not join them; poll for results
        // instead with a hard deadline.
        long deadline = System.currentTimeMillis() + joinMs;
        try {
            for (Participant p : parts) {
                while (p.applied() == null && System.currentTimeMillis() < deadline) {
                    Thread.sleep(5L);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        Map<Integer, String> applied = new LinkedHashMap<Integer, String>();
        String decision = null;
        List<TraceEvent> events = bus.events();
        for (TraceEvent e : events) {
            if ("decide".equals(e.action)) {
                String d = e.payload;
                d = d.substring("decision=".length());
                decision = d.contains(" ") ? d.substring(0, d.indexOf(' ')) : d;
            }
        }
        for (Participant p : parts) {
            int i = Integer.parseInt(p.id().substring(Names.PART.length()));
            applied.put(Integer.valueOf(i), p.applied());
        }
        String a1 = applied.get(1);
        String a2 = applied.get(2);
        boolean agreement = a1 != null && a1.equals(a2);
        return new Outcome(variant, applied, decision, agreement, events);
    }

    private static Participant make(int index, String variant, Bus bus,
                                    boolean canCommit, long delay) {
        if ("correct".equals(variant)) {
            return new CorrectParticipant(index, bus, canCommit, delay);
        }
        if ("buggy".equals(variant)) {
            return new BuggyParticipant(index, bus, canCommit, delay);
        }
        throw new IllegalArgumentException("unknown variant: " + variant);
    }

    private TwoPhaseCommit() {
    }
}
