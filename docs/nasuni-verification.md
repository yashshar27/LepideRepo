# Nasuni-specific verification checklist

## Confirmed from public Nasuni documentation

The Nasuni documentation page "Audit Events, Audit Logs, and Syslog Export" describes:
- Per-volume file-system auditing and audit log files under `.nasuni\\audit\\<description>\\<yyyymmdd>`.
- CSV-style audit fields: UTC timestamp, category, event type, path/from, new path/to, user, group, SID, share/export, volume type, client IP, snapshot timestamp and shared link.
- JSON audit examples with fields including `event_type`, `sequence`, `timestamp`, `username`, `proto`, `ipaddr`, `volume`, `path`, `newpath` and `result`.
- Syslog Export for Nasuni notifications and file-auditing messages.

Official sources:
- https://docs.nasuni.com/docs/audit-events
- https://docs.nasuni.com/docs/microsoft-sentinel
- https://docs.nasuni.com/docs/web-access-auditing

## Verify in the customer's environment before a live listener

1. Nasuni Edge Appliance, NMC and software versions.
2. Exact audit events enabled per volume; auditing may be disabled by default.
3. Exact Syslog Export configuration and destination format.
4. Transport protocol (UDP/TCP/TLS), destination port, framing, maximum message size and encoding. Do not infer protocol merely because Syslog Export exists.
5. Whether messages are plain CSV, JSON, a syslog header plus payload, or a mix of notification and audit records.
6. Whether a `LOST_EVENT` or other source-level loss indicator is emitted and how to alert on it.
7. Meaning and uniqueness scope of `sequence`; docs describe it as a rotating incrementing event ID.
8. Semantics of JSON `result`; the starter intentionally maps normalized outcome to `unknown`.
9. Confirm timestamp representation for the deployed version and preserve original values/timezone evidence.
10. Whether the source can resend/replay after a network outage, and whether any acknowledgement/checkpoint mechanism exists.
11. Expected event coverage, retention and acceptable collection lag.
12. Identity attribution caveats: Nasuni documents rare cases where audit events may associate the wrong UID when administrative users share a PID/session.

## Production readiness gaps

- Real Syslog receiver and sender-authentication strategy.
- Durable bounded queue and restart recovery.
- Durable quarantine before source progress advances.
- Production license provider and explicit expiry/outage policy.
- Secrets management, TLS/network rules and least privilege.
- Load tests, retention, backup/recovery and security review.
