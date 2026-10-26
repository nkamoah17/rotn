package com.rot.n.scheduler;

/** Thrown when a replay violates the gate: bad schedule format, step-order
 *  mismatch between actor and schedule, or an infeasible step. The demo
 *  converts this into a REPLAY-REJECTED result (exit 2), never a crash.
 */
public class GateException extends RuntimeException {
    public GateException(String message) { super(message); }
}
