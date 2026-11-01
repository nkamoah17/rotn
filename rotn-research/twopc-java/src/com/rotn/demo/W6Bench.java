package com.rot.n.demo;

import com.rot.n.twopc.Bus;
import com.rot.n.twopc.Message;

/** W6 probe-cost benchmark workload.
 *
 *  Isolates the probe's per-event overhead by driving the single instrumented
 *  choke point -- {@code Bus.record(TraceEvent)}, reached via the public
 *  {@code send()} path -- in a tight single-threaded loop with no sleeps or
 *  scheduling. {@code send()} records exactly one {@code TraceEvent} per call,
 *  so the measured cost per iteration is the native record cost plus (only when
 *  the agent is attached) the probe's {@code Probe.record()} work: JSON build +
 *  line write + flush.
 *
 *  The W6 harness (build.ps1) runs this driver twice and reports the overhead:
 *
 *    baseline     : no -javaagent     -> Bus.record does its native work only
 *    instrumented : -javaagent        -> Bus.record additionally calls Probe.record
 *
 *  overhead% = (instrumented - baseline) / baseline * 100. The baseline is a
 *  sub-microsecond in-memory path, so the % is large by construction; the
 *  harness also reports the absolute per-record ns and the added ns/record,
 *  which are the stable, interpretable numbers.
 *
 *  Emits one machine-readable line (parsed by the harness):
 *      BENCH records=N elapsed_ns=X per_record_ns=Y
 */
public final class W6Bench {
    public static void main(String[] args) throws Exception {
        int records = args.length > 0 ? Integer.parseInt(args[0]) : 200000;
        Bus bus = new Bus("src", "dst");
        final Message m = new Message(Message.Type.ASK, "src", "dst", null);
        // Warmup: let the JIT compile the hot path (identical in both runs).
        for (int i = 0; i < 20000; i++) {
            bus.send(m);
        }
        final long t0 = System.nanoTime();
        for (int i = 0; i < records; i++) {
            bus.send(m);
        }
        final long elapsed = System.nanoTime() - t0;
        System.out.printf("BENCH records=%d elapsed_ns=%d per_record_ns=%.3f%n",
                records, elapsed, (double) elapsed / records);
    }

    private W6Bench() {
    }
}
