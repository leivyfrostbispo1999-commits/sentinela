# SENTINELA Replay

Replay is intentionally lightweight in the current product tier. Historical
alerts are read from PostgreSQL, filtered by incident, host, user, IP or time
range, marked with a replay id, and re-evaluated by the API simulation path.

Heavy search backends and external queues are deliberately not required.
