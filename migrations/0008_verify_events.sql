-- 0008_verify_events.sql
-- Minimal adoption/activity telemetry for AIT verification.
--
-- One row per AIT verify (GET /verify?token=), written async via
-- ctx.waitUntil OFF the hot path, so it never adds latency to the free,
-- unlimited verify endpoint and a write failure never affects the verdict.
--
-- From this single table you derive: platforms adopting (distinct aud),
-- users per platform (distinct agent_id/operator_id per aud), call volume
-- (count), DAU (distinct agent_id per day), and tier distribution
-- (operator_tier per aud). Captures only AXIS-internal identifiers — never
-- platform content or platform users.
--
-- Scale path: at high volume, move the write to Cloudflare Analytics Engine
-- (sampled, zero-DB); the call site stays the same.

CREATE TABLE IF NOT EXISTS verify_events (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ts            INTEGER NOT NULL,   -- epoch ms (Date.now())
  aud           TEXT,               -- the platform: the AIT's `aud` claim
  agent_id      TEXT,               -- axis_id of the verifying agent
  operator_id   TEXT,               -- canonical axis:<slug>:operator
  operator_tier TEXT,               -- email|domain|verified|kyb_individual|kyb_organization
  valid         INTEGER NOT NULL,   -- 1 if the token verified, 0 otherwise
  code          TEXT                -- failure code when valid=0, else NULL
);

CREATE INDEX IF NOT EXISTS idx_verify_events_ts ON verify_events (ts);
CREATE INDEX IF NOT EXISTS idx_verify_events_aud_ts ON verify_events (aud, ts);
