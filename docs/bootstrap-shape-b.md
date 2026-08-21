# Shape B bootstrap — retired

Status: **QUARANTINED / NOT AN OPERATOR RUNBOOK**.

The historical GitHub App and Backblaze B2 bootstrap procedure is intentionally
removed. Do not create, install, expand, or re-key provider authority from this
document. The checked-in App manifest is metadata-read-only inventory, and the
former one-click App creation page no longer exists.

A future bootstrap requires a separately approved RFC and runbook covering:

- job-specific least-privilege identities and short-lived credentials;
- protected human approval without administrator bypass;
- transactional evidence fencing, recovery, and provider rollback;
- exact repository, workflow, environment, tag-object, and commit binding; and
- independently verified provider evidence before activation.

Until those controls are reviewed and implemented, use the operational
quarantine checklist in the repository README.
