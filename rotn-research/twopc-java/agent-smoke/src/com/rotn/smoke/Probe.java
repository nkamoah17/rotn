package com.rot.n.smoke;

/** Probe target: the smoke agent inserts a call to enter() at the start of
 *  App.<init>. If the probe fires, the -javaagent + ASM transform pipeline works. */
public final class Probe {
    public static void enter(String site) {
        System.out.println("SMOKE-PROBE " + site);
    }

    private Probe() {
    }
}
