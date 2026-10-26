package com.rot.n.demo;

import com.rot.n.twopc.TwoPhaseCommit;

/** W2 single-run trace driver.
 *
 *  Runs ONE 2PC round for the given variant and reports the outcome. The
 *  probe agent (when attached) emits the trace for this JVM run to the path
 *  named by -Drotn.probe.trace / ROTN_PROBE_TRACE.
 *
 *  Exit code: 0 = the run completed (agreement or not -- the agreement
 *  verdict is the W4 conformance checker's job); nonzero = the JVM itself
 *  failed (e.g. probe init error).
 */
public final class TraceDemo {
    public static void main(String[] args) {
        String variant = args.length > 0 ? args[0] : "buggy";
        TwoPhaseCommit.Outcome oc = TwoPhaseCommit.run(variant, 150L, 400L);
        System.out.printf("variant=%s decision=%s applied=%s agreement=%s events=%d%n",
                oc.variant, oc.decision, oc.applied, oc.agreement, oc.trace.size());
        System.exit(0);
    }

    private TraceDemo() {
    }
}
