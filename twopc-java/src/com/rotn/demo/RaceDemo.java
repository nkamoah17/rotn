package com.rot.n.demo;

import com.rot.n.twopc.TwoPhaseCommit;
import com.rot.n.twopc.TraceEvent;

/** W1 demonstration: the seeded 2PC bug is runtime-visible.
 *
 *   correct variant : agreement holds on every run (both apply abort)
 *   buggy   variant : agreement violated (p1 self-commits, p2 self-aborts)
 *
 * Exit code: 0 = correct clean AND at least one buggy violation (the witness
 * trace is printed); 1 = otherwise.
 */
public final class RaceDemo {
    public static void main(String[] args) {
        int runs = 20;
        int correctBad = 0;
        int buggyBad = 0;
        TwoPhaseCommit.Outcome witness = null;

        for (int i = 0; i < runs; i++) {
            TwoPhaseCommit.Outcome oc = TwoPhaseCommit.run("correct", 150L, 400L);
            if (!oc.agreement) {
                correctBad++;
            }
            TwoPhaseCommit.Outcome ob = TwoPhaseCommit.run("buggy", 150L, 400L);
            if (!ob.agreement) {
                buggyBad++;
                if (witness == null) {
                    witness = ob;
                }
            }
        }

        System.out.printf("correct : %d/%d runs violated agreement%n", correctBad, runs);
        System.out.printf("buggy   : %d/%d runs violated agreement%n", buggyBad, runs);
        if (witness != null) {
            System.out.println("witness (buggy): decision=" + witness.decision
                    + " applied=" + witness.applied);
            for (TraceEvent e : witness.trace) {
                System.out.println("  " + e.describe());
            }
        }
        boolean ok = (correctBad == 0) && (buggyBad >= 1);
        System.out.println(ok ? "RACE-DEMO PASS" : "RACE-DEMO FAIL");
        System.exit(ok ? 0 : 1);
    }

    private RaceDemo() {
    }
}
