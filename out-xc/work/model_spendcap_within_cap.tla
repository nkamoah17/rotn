---- MODULE model_spendcap_within_cap ----

EXTENDS Integers

VARIABLE
  \* @type: Int;
  completed,
  \* @type: Int;
  inflight

Init ==
  completed = 0
  /\ inflight = 0

spend_ok ==
  ((completed + 100) <= 200) /\ (inflight < 3)
  /\ inflight' = (inflight + 1)
  /\ UNCHANGED << completed >>

spend_deny ==
  ~((completed + 100) <= 200)
  /\ UNCHANGED << completed, inflight >>

respond ==
  inflight >= 1
  /\ inflight' = (inflight - 1)
  /\ completed' = (completed + 100)

busy ==
  UNCHANGED << completed, inflight >>

Next ==
  spend_ok
  \/ spend_deny
  \/ respond
  \/ busy

\* @type: << Int, Int >>;
vars == << completed, inflight >>

Spec ==
  Init
  /\ [][Next]_vars

SpendcapWithinCap ==
  (completed + (inflight * 100)) <= 200

====
