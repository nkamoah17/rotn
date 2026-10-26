package com.rot.n.tests;

import com.rot.n.scheduler.ScheduleReader;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

/** Test helper: build a valid witness-schedule file and return its parsed
 *  steps (the public-API path, since ScheduleReader.Step is package-private).
 *
 *  Owner/action names and step numbers follow the W3 schedule contract.
 */
final class Sched {
    private Sched() {}

    /** ownerAction = owner1, action1, owner2, action2, ... (step i is 0-based). */
    static List<ScheduleReader.Step> steps(String... ownerAction) {
        int n = ownerAction.length / 2;
        StringBuilder sb = new StringBuilder();
        sb.append("{\"_meta\":\"rotn-schedule\",\"format\":\"v1\",\"n_steps\":")
          .append(n).append("}\n");
        for (int i = 0; i < n; i++) {
            sb.append("{\"owner\":\"").append(ownerAction[2 * i])
              .append("\",\"action\":\"").append(ownerAction[2 * i + 1])
              .append("\",\"step\":").append(i).append("}\n");
        }
        try {
            File f = File.createTempFile("rotn-sched-test", ".jsonl");
            f.deleteOnExit();
            Files.write(f.toPath(), sb.toString().getBytes(StandardCharsets.UTF_8));
            return ScheduleReader.load(f).steps;
        } catch (Exception e) {
            throw new RuntimeException("Sched.steps failed: " + e, e);
        }
    }
}