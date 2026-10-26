package com.rot.n.twopc;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/** Star message bus (coordinator <-> participants). Environment layer.
 *
 *  Every protocol event -- transport (SEND/RECV) and spec (vote/decide/apply) --
 *  passes through record(), which assigns the global total order (seq) under a
 *  single lock. This single choke point is what the W2 probe and the W3
 *  scheduler build on; the target protocol code stays probe-free.
 */
public final class Bus {
    private static final AtomicLong SEQ = new AtomicLong();

    private final Map<String, BlockingQueue<Message>> inboxes =
            new HashMap<String, BlockingQueue<Message>>();
    private final List<TraceEvent> events = new ArrayList<TraceEvent>();

    public Bus(String... endpoints) {
        for (String e : endpoints) {
            inboxes.put(e, new LinkedBlockingQueue<Message>());
        }
    }

    /** Assign the total-order seq and append. Sole choke point for trace events. */
    public void record(TraceEvent e) {
        synchronized (events) {
            e.seq = SEQ.getAndIncrement();
            events.add(e);
        }
    }

    public void send(Message m) throws InterruptedException {
        inboxes.get(m.to).put(m);
        record(TraceEvent.transport(TraceEvent.Kind.SEND, m.from, "send_" + m.type, m.describe()));
    }

    /** Blocks up to timeoutMs for a message addressed to this thread's endpoint. */
    public Message recv(long timeoutMs) throws InterruptedException {
        BlockingQueue<Message> q = inboxes.get(Thread.currentThread().getName());
        Message m = q.poll(timeoutMs, TimeUnit.MILLISECONDS);
        if (m != null) {
            record(TraceEvent.transport(TraceEvent.Kind.RECV,
                    Thread.currentThread().getName(), "recv_" + m.type, m.describe()));
        }
        return m;
    }

    /** Non-blocking receive for an explicit endpoint (W3 replay driver).
     *  Records the RECV transport event like {@link #recv(long)}. */
    public Message poll(String endpoint) {
        BlockingQueue<Message> q = inboxes.get(endpoint);
        if (q == null) {
            return null;
        }
        Message m = q.poll();
        if (m != null) {
            record(TraceEvent.transport(TraceEvent.Kind.RECV,
                    endpoint, "recv_" + m.type, m.describe()));
        }
        return m;
    }

    public List<TraceEvent> events() {
        synchronized (events) {
            return new ArrayList<TraceEvent>(events);
        }
    }
}
