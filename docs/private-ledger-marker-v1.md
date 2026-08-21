# Private-ledger marker v1 migration note

The historical private-ledger field value
`dpone release controller CLOSED / PASS / GO` is hashed into existing receipt
bytes. It remains accepted only as `HISTORICAL_WIRE_OUTPUT_TITLE`; it is not an
operator verdict and grants no public release authority.

New operator-facing output must use
`INTERNAL LEDGER MARKER / NOT PUBLIC RELEASE AUTHORITY`. Replacing the v1 wire
value requires a separately versioned receipt/marker contract, new reference
vectors, and an explicit migration for existing ledger readers. Silent
replacement would invalidate historical receipt identities and is forbidden.
