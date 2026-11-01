package com.rot.n.probe;

import com.rot.n.twopc.TraceEvent;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/** W2 production probe sink: total-order metadata + JSON trace emission.
 *
 *  The agent ({@code com.rot.n.agent.ProbeAgent}) instruments
 *  {@code Bus.record()} so that every trace event reaches
 *  {@link #record(Object, TraceEvent)} AFTER its global seq has been
 *  assigned. For each event the probe keeps:
 *
 *    gseq    -- probe global sequence, 0-based, strictly monotone
 *    lamport -- total-order metadata: max(prev_lamport, seq) + 1, which is
 *               itself strictly monotone and dominates the target seq, i.e.
 *               a valid total-order extension of the lock sequence
 *
 *  and appends one JSON object per event (JSONL) to a single trace file,
 *  one file per JVM run. The header is written at init, the trailer by a
 *  shutdown hook, so even a hard exit leaves a parseable file.
 *
 *  Failures inside the probe never break the target protocol: record()
 *  swallows errors after the first one is reported.
 */
public final class Probe {
    private static final Object LOCK = new Object();
    private static final AtomicBoolean INIT_DONE = new AtomicBoolean(false);
    private static final AtomicBoolean FAIL_REPORTED = new AtomicBoolean(false);

    private static Writer writer;
    private static long gseq = -1L;
    private static long lamport = 0L;
    private static int eventCount = 0;
    private static Set<String> filterKinds = null;  // null = record all kinds
    private static String filterValue = null;       // canonical header value

    /** Resolve the trace path, open the file, emit the header, install the
     *  trailer shutdown hook. Idempotent. Called from the agent premain. */
    public static void init() {
        if (!INIT_DONE.compareAndSet(false, true)) {
            return;
        }
        String p = System.getProperty("rotn.probe.trace");
        if (p == null || p.isEmpty()) {
            p = System.getenv("ROTN_PROBE_TRACE");
        }
        if (p == null || p.isEmpty()) {
            p = "trace.jsonl";
        }
        try {
            // W7 logging-policy filter (optional, -Drotn.probe.filter):
            // comma-separated event kinds to record; unset/empty = record all
            // (the W2 default). Read once here so the header below can carry
            // the policy for trace provenance.
            String filt = System.getProperty("rotn.probe.filter");
            if (filt != null) {
                Set<String> s = new HashSet<String>();
                StringBuilder sb = new StringBuilder();
                for (String tok : filt.split(",")) {
                    String t = tok.trim().toUpperCase();
                    if (t.length() > 0) {
                        s.add(t);
                        if (sb.length() > 0) {
                            sb.append(',');
                        }
                        sb.append(t);
                    }
                }
                if (!s.isEmpty()) {
                    filterKinds = s;
                    filterValue = sb.toString();
                }
            }
            File f = new File(p);
            File dir = f.getAbsoluteFile().getParentFile();
            if (dir != null) {
                dir.mkdirs();
            }
            writer = new BufferedWriter(new OutputStreamWriter(
                    new FileOutputStream(f), StandardCharsets.UTF_8));
            Map<String, Object> h = new LinkedHashMap<String, Object>();
            h.put("_meta", "rotn-probe-header");
            h.put("format", "v1");
            String runId = System.getProperty("rotn.probe.run");
            if (runId == null || runId.isEmpty()) {
                runId = Long.toHexString(System.nanoTime());
            }
            h.put("run", runId);
            h.put("java", System.getProperty("java.version"));
            h.put("jvm", System.getProperty("java.vm.name"));
            h.put("agent", "rotn-probe/1.0");
            if (filterKinds != null) {
                h.put("filter", filterValue);
            }
            writeLine(h);
            Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
                public void run() {
                    try {
                        synchronized (LOCK) {
                            if (writer != null) {
                                Map<String, Object> t = new LinkedHashMap<String, Object>();
                                t.put("_meta", "rotn-probe-trailer");
                                t.put("events", Integer.valueOf(eventCount));
                                if (eventCount > 0) {
                                    t.put("last_gseq", Long.valueOf(gseq));
                                    t.put("last_lamport", Long.valueOf(lamport));
                                }
                                writeLine(t);
                                writer.close();
                                writer = null;
                            }
                        }
                    } catch (Exception ignored) {
                        // best effort at shutdown; never throw from a hook
                    }
                }
            }));
            System.out.println("PROBE init: " + f.getAbsolutePath());
        } catch (Exception e) {
            System.err.println("PROBE init failed: " + e);
        }
    }

    /** Called by the agent-instrumented Bus.record(), after seq is assigned. */
    public static void record(Object bus, TraceEvent e) {
        try {
            synchronized (LOCK) {
                if (writer == null) {
                    init();
                }
                if (writer == null) {
                    return;
                }
                // W7 logging policy: skip disabled event classes. gseq/lamport
                // advance only for RECORDED events, so the emitted trace stays
                // 0-based gap-free and strictly monotone (W2 gate intact).
                if (filterKinds != null
                        && (e == null || e.kind == null
                            || !filterKinds.contains(e.kind.name()))) {
                    return;
                }
                gseq++;
                long s = e.seq;
                if (s > lamport) {
                    lamport = s;
                }
                lamport++;
                eventCount++;
                Map<String, Object> m = new LinkedHashMap<String, Object>();
                m.put("gseq", Long.valueOf(gseq));
                m.put("seq", Long.valueOf(s));
                m.put("lamport", Long.valueOf(lamport));
                m.put("actor", e.actor);
                m.put("thread", e.thread);
                m.put("kind", e.kind == null ? null : e.kind.name());
                m.put("action", e.action);
                m.put("payload", e.payload);
                writeLine(m);
            }
        } catch (Throwable t) {
            if (FAIL_REPORTED.compareAndSet(false, true)) {
                System.err.println("PROBE record failed: " + t);
            }
        }
    }

    private static void writeLine(Map<String, Object> m) throws Exception {
        writer.write(json(m));
        writer.write('\n');
        writer.flush();
    }

    /** Minimal JSON object writer (string/number/null values only). */
    private static String json(Map<String, Object> m) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> en : m.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('"').append(esc(en.getKey())).append("\":");
            Object v = en.getValue();
            if (v == null) {
                sb.append("null");
            } else if (v instanceof Number) {
                sb.append(v.toString());
            } else {
                sb.append('"').append(esc(v.toString())).append('"');
            }
        }
        sb.append('}');
        return sb.toString();
    }

    private static String esc(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    private Probe() {
    }
}
