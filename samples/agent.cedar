// Minimal Cedar policy for the ROTN policy front-end smoke test.
// The adapter pins the non-vacuity property: the policy set permits at
// least one concrete request (decision == True in some reachable state).

entity User;
entity Account;

action read_log;
action update_balance;
action exfiltrate_secret;

// Permit the two harmless actions ...
permit (principal, action, resource) when { action == read_log };
permit (principal, action, resource) when { action == update_balance };

// ... and forbid the harmful one (Cedar is default-deny, and forbid
// overrides permit).
forbid (principal, action, resource) when { action == exfiltrate_secret };
