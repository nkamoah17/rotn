package com.rot.n.twopc;

import com.rot.n.scheduler.Gate;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** 2PC coordinator (owner "coordinator").
 *
 *  Asks every participant, collects votes until the deadline, decides
 *  (commit iff every participant voted yes; abort otherwise), and
 *  broadcasts the decision. A vote that arrives after the deadline is
 *  too late -- the coordinator already decided.
 */
public final class Coordinator extends Thread {
    private final Bus bus;
    private final List<Integer> indices;
    private final long timeoutMs;

    public Coordinator(Bus bus, List<Integer> indices, long timeoutMs) {
        super(Names.COORD);
        this.bus = bus;
        this.indices = indices;
        this.timeoutMs = timeoutMs;
        setDaemon(true);
    }

    @Override
    public void run() {
        try {
            askAll();
            Map<Integer, String> votes = new LinkedHashMap<Integer, String>();
            long deadline = System.currentTimeMillis() + timeoutMs;
            while (votes.size() < indices.size() && System.currentTimeMillis() < deadline) {
                Message m = bus.recv(10);
                if (m != null && m.type == Message.Type.VOTE) {
                    votes.put(Integer.valueOf(indexOf(m.from)), m.value);
                }
            }
            decide(votes);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** Broadcast the prepare ASK to all participants (transport only). */
    public final void askAll() throws InterruptedException {
        for (Integer i : indices) {
            bus.send(new Message(Message.Type.ASK, Names.COORD, Names.PART + i, null));
        }
    }

    /** W3 replay: drain the VOTEs already collected on the wire, decide
     *  (gate-checked spec record) and broadcast the DECISION. */
    public final String replayDecide() throws InterruptedException {
        Map<Integer, String> votes = new LinkedHashMap<Integer, String>();
        Message m;
        while ((m = bus.poll(Names.COORD)) != null) {
            if (m.type == Message.Type.VOTE) {
                votes.put(Integer.valueOf(indexOf(m.from)), m.value);
            }
        }
        return decide(votes);
    }

    private String decide(Map<Integer, String> votes) throws InterruptedException {
        String decision = "commit";
        if (votes.size() != indices.size()) {
            decision = "abort";
        }
        for (String v : votes.values()) {
            if ("no".equals(v)) {
                decision = "abort";
            }
        }
        Gate.check(Names.COORD, "decide");
        bus.record(TraceEvent.spec(Names.COORD, "decide",
                "decision=" + decision + " votes=" + votes));
        for (Integer i : indices) {
            bus.send(new Message(Message.Type.DECISION, Names.COORD, Names.PART + i, decision));
        }
        return decision;
    }

    private static int indexOf(String owner) {
        return Integer.parseInt(owner.substring(Names.PART.length()));
    }
}
