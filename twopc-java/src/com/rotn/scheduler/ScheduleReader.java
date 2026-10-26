package com.rot.n.scheduler;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Parses and validates the Phase 2 witness-schedule JSONL contract:
 *  first line {"_meta":"rotn-schedule", ...}, then one
 *  {"owner","action","step"} record per gate step, step 0-based and
 *  consecutive. Emits GateException on any violation.
 */
public final class ScheduleReader {

    public static final class Step {
        public final String owner;
        public final String action;
        public final int step;
        Step(String owner, String action, int step) {
            this.owner = owner;
            this.action = action;
            this.step = step;
        }
        @Override public String toString() {
            return "step" + step + " (" + owner + ", " + action + ")";
        }
    }

    public static final class Schedule {
        public final Map<String, Object> header;
        public final List<Step> steps;
        Schedule(Map<String, Object> header, List<Step> steps) {
            this.header = header;
            this.steps = steps;
        }
    }

    private ScheduleReader() {}

    public static Schedule load(File f) throws GateException {
        if (!f.isFile()) {
            throw new GateException("schedule file not found: " + f);
        }
        Map<String, Object> header = null;
        List<Step> steps = new ArrayList<Step>();
        List<String> lines = readLines(f);
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.trim().length() == 0) {
                continue;
            }
            Object obj;
            try {
                obj = JsonLine.parse(line);
            } catch (Exception exc) {
                throw new GateException("line " + (i + 1) + ": not valid JSON: " + exc.getMessage());
            }
            if (!(obj instanceof Map)) {
                throw new GateException("line " + (i + 1) + ": expected a JSON object");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> rec = (Map<String, Object>) obj;
            Object meta = rec.get("_meta");
            if (meta != null) {
                if (!"rotn-schedule".equals(meta)) {
                    throw new GateException("line " + (i + 1) + ": bad _meta " + meta + " (expected rotn-schedule)");
                }
                if (header != null) {
                    throw new GateException("line " + (i + 1) + ": duplicate schedule header");
                }
                header = rec;
            } else {
                if (header == null) {
                    throw new GateException("line " + (i + 1) + ": step record before header");
                }
                Object o = rec.get("owner");
                Object a = rec.get("action");
                Object s = rec.get("step");
                if (!(o instanceof String) || !(a instanceof String)) {
                    throw new GateException("line " + (i + 1) + ": step needs string owner/action");
                }
                long n = asLong(s, -1L);
                if (n != steps.size()) {
                    throw new GateException("line " + (i + 1) + ": step " + s + " out of order (expected " + steps.size() + ")");
                }
                steps.add(new Step((String) o, (String) a, (int) n));
            }
        }
        if (header == null) {
            throw new GateException("no header line with _meta=rotn-schedule");
        }
        if (!"v1".equals(header.get("format"))) {
            throw new GateException("unsupported format " + header.get("format") + " (expected v1)");
        }
        long declared = asLong(header.get("n_steps"), -1L);
        if (declared != steps.size()) {
            throw new GateException("header n_steps=" + declared + " but " + steps.size() + " step records");
        }
        if (steps.isEmpty()) {
            throw new GateException("schedule has no gate steps");
        }
        return new Schedule(header, steps);
    }

    private static long asLong(Object o, long dflt) {
        if (o instanceof Long) {
            return (Long) o;
        }
        return dflt;
    }

    private static List<String> readLines(File f) throws GateException {
        List<String> out = new ArrayList<String>();
        InputStream in = null;
        BufferedReader br = null;
        try {
            in = new FileInputStream(f);
            br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String line;
            while ((line = br.readLine()) != null) {
                out.add(line);
            }
        } catch (IOException exc) {
            throw new GateException("cannot read schedule: " + exc.getMessage());
        } finally {
            closeQuietly(br);
            closeQuietly(in);
        }
        return out;
    }

    private static void closeQuietly(java.io.Closeable c) {
        if (c != null) {
            try { c.close(); } catch (IOException ignored) { }
        }
    }
}
