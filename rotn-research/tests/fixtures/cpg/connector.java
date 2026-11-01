// connector.java -- the spend-cap + exfiltration connector that
// connector.cpg.json (the committed CPG fixture) is a scrape of.  The
// offline tests run against the JSON, not this file; this source is the
// provenance that keeps every node id / edge / classifier decision in the
// fixture traceable to concrete lines.
package com.acme.guard;

public class Connector {
    private final int cap;
    private int settled;
    private int inflight;
    private final AuditLog audit;

    public Connector(int cap, int settled, int inflight, AuditLog audit) {
        this.cap = cap;
        this.settled = settled;
        this.inflight = inflight;
        this.audit = audit;
    }

    // Spend-cap control: in-flight aware, so a parallel burst of requests
    // cannot overshoot the cap (the budget shape, enforced).
    public boolean canSpend(int amount) {
        int projected = settled + inflight + amount;
        return projected <= cap;
    }

    // Exfiltration path: the private parameter ssn flows through mask()
    // into the egress sink AuditLog.send -- the private->sink edge that
    // CpgModel.taint_path must find.
    public void report(String ssn) {
        String payload = mask(ssn);
        audit.send(payload);
    }

    private String mask(String ssn) {
        return ssn;   // identity: private data reaches the sink unchanged
    }
}

interface AuditLog {
    void send(String payload);
}