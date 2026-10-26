package com.rot.n.tests;

import static org.junit.Assert.*;

import com.rot.n.scheduler.GateException;
import com.rot.n.scheduler.ScheduleReader;

import org.junit.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/** W5 — witness-schedule parser + validation (the "witness" the gate checks).
 *
 *  A schedule is a JSONL file: exactly one header line (_meta=rotn-schedule,
 *  format=v1, n_steps=N) followed by N step records with consecutive 0-based
 *  step numbers and string owner/action. Anything else is rejected.
 */
public class ScheduleReaderTest {

    private static File write(String content) throws Exception {
        File f = File.createTempFile("rotn-sched", ".jsonl");
        f.deleteOnExit();
        Files.write(f.toPath(), content.getBytes(StandardCharsets.UTF_8));
        return f;
    }

    private static String schedule(int n, String... ownerAction) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"_meta\":\"rotn-schedule\",\"format\":\"v1\",\"n_steps\":").append(n).append("}\n");
        for (int i = 0; i < n; i++) {
            sb.append("{\"owner\":\"").append(ownerAction[2 * i])
              .append("\",\"action\":\"").append(ownerAction[2 * i + 1])
              .append("\",\"step\":").append(i).append("}\n");
        }
        return sb.toString();
    }

    private static void assertReject(String content, String messagePart) {
        File f;
        try {
            f = write(content);
        } catch (Exception e) {
            throw new RuntimeException("test setup failed", e);
        }
        try {
            ScheduleReader.load(f);
            fail("expected GateException (message containing: " + messagePart + ")");
        } catch (GateException e) {
            assertTrue("unexpected message: " + e.getMessage(),
                    e.getMessage().contains(messagePart));
        }
    }

    @Test
    public void valid_schedule_loads() throws Exception {
        ScheduleReader.Schedule s = ScheduleReader.load(
                write(schedule(2, "coordinator", "decide", "participant_1", "apply_1")));
        assertEquals(2, s.steps.size());
        assertEquals("coordinator", s.steps.get(0).owner);
        assertEquals("decide", s.steps.get(0).action);
        assertEquals(0, s.steps.get(0).step);
        assertEquals("participant_1", s.steps.get(1).owner);
    }

    @Test
    public void missing_file_throws() {
        try {
            ScheduleReader.load(new File("no-such-file-12345.jsonl"));
            fail("expected GateException");
        } catch (GateException e) {
            assertTrue(e.getMessage().contains("not found"));
        }
    }

    @Test
    public void step_before_header_throws() {
        assertReject("{\"owner\":\"coordinator\",\"action\":\"decide\",\"step\":0}\n",
                     "before header");
    }

    @Test
    public void bad_meta_throws() {
        assertReject("{\"_meta\":\"wrong\",\"format\":\"v1\",\"n_steps\":1}\n"
                   + "{\"owner\":\"coordinator\",\"action\":\"decide\",\"step\":0}\n",
                   "_meta");
    }

    @Test
    public void bad_format_throws() {
        assertReject("{\"_meta\":\"rotn-schedule\",\"format\":\"v2\",\"n_steps\":1}\n"
                   + "{\"owner\":\"coordinator\",\"action\":\"decide\",\"step\":0}\n",
                   "format");
    }

    @Test
    public void duplicate_header_throws() {
        assertReject("{\"_meta\":\"rotn-schedule\",\"format\":\"v1\",\"n_steps\":1}\n"
                   + "{\"_meta\":\"rotn-schedule\",\"format\":\"v1\",\"n_steps\":1}\n"
                   + "{\"owner\":\"coordinator\",\"action\":\"decide\",\"step\":0}\n",
                   "duplicate");
    }

    @Test
    public void out_of_order_step_throws() {
        assertReject("{\"_meta\":\"rotn-schedule\",\"format\":\"v1\",\"n_steps\":2}\n"
                   + "{\"owner\":\"coordinator\",\"action\":\"decide\",\"step\":0}\n"
                   + "{\"owner\":\"participant_1\",\"action\":\"apply_1\",\"step\":5}\n",
                   "out of order");
    }

    @Test
    public void n_steps_mismatch_throws() {
        assertReject("{\"_meta\":\"rotn-schedule\",\"format\":\"v1\",\"n_steps\":5}\n"
                   + "{\"owner\":\"coordinator\",\"action\":\"decide\",\"step\":0}\n",
                   "n_steps");
    }

    @Test
    public void empty_steps_throws() {
        assertReject("{\"_meta\":\"rotn-schedule\",\"format\":\"v1\",\"n_steps\":0}\n",
                   "no gate steps");
    }

    @Test
    public void non_string_owner_throws() {
        assertReject("{\"_meta\":\"rotn-schedule\",\"format\":\"v1\",\"n_steps\":1}\n"
                   + "{\"owner\":123,\"action\":\"decide\",\"step\":0}\n",
                   "string owner/action");
    }
}