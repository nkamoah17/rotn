package com.rot.n.demo;

import com.rot.n.scheduler.Gate;
import com.rot.n.scheduler.GateException;
import com.rot.n.scheduler.ScheduleReader;
import com.rot.n.twopc.BuggyParticipant;
import com.rot.n.twopc.Bus;
import com.rot.n.twopc.Coordinator;
import com.rot.n.twopc.CorrectParticipant;
import com.rot.n.twopc.Message;
import com.rot.n.twopc.Names;
import com.rot.n.twopc.Participant;

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** W3 gated replay driver: the witness schedule drives a single-threaded,
 *  deterministic replay of the 2PC protocol.
 *
 *  Usage:
 *    java com.rot.n.demo.ReplayDemo <variant:buggy|correct> <schedule.jsonl>
 *
 *  For every schedule step the driver performs exactly that action in
 *  exactly that order; the gate (Gate.check inside spec()/decide) rejects
 *  any mismatch between the schedule and what the protocol actually does.
 *  The driver runs on the main thread and never sleeps, so the probe trace
 *  is byte-identical across repeated replays of the same schedule+variant:
 *  stable run id (-Drotn.probe.run), stable thread name ("main"), stable
 *  gseq/seq/lamport, gate-ordered events.
 *
 *  Verdict (W3):
 *    CONFORMANT     -- replay completed, every participant applied,
 *                      and all applied values agree
 *    NON-CONFORMANT -- replay completed, but some participant did not
 *                      apply or the applied values disagree
 *    REJECTED       -- schedule invalid/infeasible (GateException)
 *
 *  Exit codes: 0 = CONFORMANT, 10 = NON-CONFORMANT, 20 = REJECTED,
 *  2 = usage error.
 */
public final class ReplayDemo {
    private static final Pattern VOTE_RE = Pattern.compile("^vote_(\\d+)_(yes|no)$");
    private static final Pattern APPLY_RE = Pattern.compile("^apply_(\\d+)$");

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("usage: ReplayDemo <buggy|correct> <schedule.jsonl>");
            System.exit(2);
        }
        String variant = args[0];
        File schedFile = new File(args[1]);
        try {
            ReplayResult r = replay(variant, schedFile);
            System.out.println("W3 REPLAY: variant=" + variant
                    + " schedule=" + schedFile.getAbsolutePath()
                    + " steps=" + r.steps
                    + " decision=" + r.decision
                    + " applied=" + r.applied
                    + " events=" + r.events);
            System.out.println("W3 VERDICT: " + r.verdict);
            System.exit("CONFORMANT".equals(r.verdict) ? 0 : 10);
        } catch (GateException e) {
            System.out.println("W3 REPLAY: variant=" + variant
                    + " schedule=" + schedFile.getAbsolutePath());
            System.out.println("W3 VERDICT: REJECTED reason=" + e.getMessage());
            System.exit(20);
        } catch (Exception e) {
            System.err.println("W3 REPLAY failed: " + e);
            e.printStackTrace(System.err);
            System.exit(3);
        }
    }

    private static final class ReplayResult {
        String verdict;
        String decision;
        int steps;
        Map<Integer, String> applied;
        int events;
    }

    private static ReplayResult replay(String variant, File schedFile) throws Exception {
        ScheduleReader.Schedule sched = ScheduleReader.load(schedFile);
        Map<Integer, Participant> parts = new LinkedHashMap<Integer, Participant>();
        String decision = null;
        Gate gate = new Gate(sched.steps);
        Gate.activate(gate);
        try {
            Bus bus = new Bus(Names.COORD, Names.PART + 1, Names.PART + 2);
            List<Integer> indices = new ArrayList<Integer>();
            indices.add(Integer.valueOf(1));
            indices.add(Integer.valueOf(2));
            Coordinator coordinator = new Coordinator(bus, indices, 150L);
            parts.put(Integer.valueOf(1), make(1, variant, bus, true, 10L));
            parts.put(Integer.valueOf(2), make(2, variant, bus, false, 400L));

            // Prepare-phase transport: the coordinator broadcasts ASK to every
            // participant. Transport is not a gate step; it makes the first
            // vote feasible.
            coordinator.askAll();

            for (int i = 0; i < sched.steps.size(); i++) {
                ScheduleReader.Step st = sched.steps.get(i);
                if ("decide".equals(st.action)) {
                    decision = coordinator.replayDecide();
                } else {
                    perform(st, parts, bus);
                }
            }

            Map<Integer, String> applied = new LinkedHashMap<Integer, String>();
            boolean allApplied = true;
            for (Map.Entry<Integer, Participant> en : parts.entrySet()) {
                String v = en.getValue().applied();
                applied.put(en.getKey(), v);
                if (v == null) {
                    allApplied = false;
                }
            }
            String a1 = applied.get(1);
            String a2 = applied.get(2);
            boolean agreement = allApplied && a1 != null && a1.equals(a2);

            ReplayResult r = new ReplayResult();
            r.verdict = agreement ? "CONFORMANT" : "NON-CONFORMANT";
            r.decision = decision;
            r.steps = sched.steps.size();
            r.applied = applied;
            r.events = bus.events().size();
            return r;
        } finally {
            Gate.deactivate();
        }
    }

    /** Perform one non-coordinator gate step (vote_<i>_<v> / apply_<i>, or
     *  the init/done no-ops). Feasibility is checked against the in-flight
     *  wire state; the gate check happens inside the protocol code. */
    private static void perform(ScheduleReader.Step st,
                                Map<Integer, Participant> parts, Bus bus) throws Exception {
        String a = st.action;
        if ("init".equals(a) || "done".equals(a)) {
            // Replay no-op: consume the gate step and move on.
            Gate g = Gate.active;
            if (g != null) {
                g.consume(st.owner, a);
            }
            return;
        }
        Matcher m = VOTE_RE.matcher(a);
        if (m.matches()) {
            int idx = Integer.parseInt(m.group(1));
            Participant p = parts.get(Integer.valueOf(idx));
            if (p == null) {
                throw new GateException("step " + st.step + ": unknown participant in " + a);
            }
            Message ask = bus.poll(p.id());
            if (ask == null || ask.type != Message.Type.ASK) {
                throw new GateException("step " + st.step + ": " + a + " infeasible: no ASK in flight for " + p.id());
            }
            p.replayVote();
            return;
        }
        Matcher am = APPLY_RE.matcher(a);
        if (am.matches()) {
            int idx = Integer.parseInt(am.group(1));
            Participant p = parts.get(Integer.valueOf(idx));
            if (p == null) {
                throw new GateException("step " + st.step + ": unknown participant in " + a);
            }
            Message d = bus.poll(p.id());
            if (d == null || d.type != Message.Type.DECISION) {
                throw new GateException("step " + st.step + ": " + a + " infeasible: no DECISION in flight for " + p.id());
            }
            p.replayApply(d);
            return;
        }
        throw new GateException("step " + st.step + ": unknown gate action " + a);
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

    private ReplayDemo() {
    }
}