-- ScamShield AI — D1 schema
-- Privacy by design: no message text, no phone numbers, no full URLs with paths, no IP addresses are stored.
-- A report is a structural fingerprint: brand, scam type, domain, signal ids, score.

CREATE TABLE IF NOT EXISTS ss_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  channel TEXT NOT NULL,              -- sms | whatsapp | email | web | extension | api | qr
  brand TEXT,                         -- impersonated brand id
  playbook TEXT,                      -- scam type id
  domain TEXT,                        -- registrable domain only (e.g. rta-fines-ae.top)
  domain_shape TEXT,                  -- domain with digits masked, for campaign clustering
  tld TEXT,
  free_host TEXT,
  verdict TEXT,
  score INTEGER,
  signals TEXT,                       -- comma separated signal ids
  emirate TEXT,                       -- optional, user-chosen (AD / DXB / SHJ ...)
  lost_money INTEGER DEFAULT 0,       -- user ticked "I lost money" (triggers priority)
  campaign_id INTEGER,
  demo INTEGER DEFAULT 0              -- 1 = synthetic demo data, filterable in dashboard
);
CREATE INDEX IF NOT EXISTS idx_ss_reports_created ON ss_reports(created_at);
CREATE INDEX IF NOT EXISTS idx_ss_reports_domain ON ss_reports(domain);
CREATE INDEX IF NOT EXISTS idx_ss_reports_campaign ON ss_reports(campaign_id);

CREATE TABLE IF NOT EXISTS ss_campaigns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT UNIQUE NOT NULL,           -- brand|playbook|tld
  brand TEXT,
  playbook TEXT,
  tld TEXT,
  first_seen TEXT,
  last_seen TEXT,
  reports INTEGER DEFAULT 0,
  victims INTEGER DEFAULT 0,          -- reports with lost_money = 1
  domains TEXT DEFAULT '[]',          -- JSON array of distinct domains
  status TEXT DEFAULT 'active',       -- active | takedown_requested | down
  demo INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ss_hunts (
  domain TEXT PRIMARY KEY,            -- look-alike domain found proactively
  brand TEXT,
  source TEXT,                        -- ct (certificate transparency) | dns (permutation scan)
  first_seen TEXT DEFAULT (datetime('now')),
  detail TEXT,                        -- cert issue date / resolving IPs
  score INTEGER,
  status TEXT DEFAULT 'new'           -- new | watching | takedown_requested | down | false_positive
);

CREATE TABLE IF NOT EXISTS ss_daily (
  day TEXT NOT NULL,
  kind TEXT NOT NULL,                 -- url | message | screenshot | qr
  verdict TEXT NOT NULL,
  n INTEGER DEFAULT 0,
  PRIMARY KEY (day, kind, verdict)
);

CREATE TABLE IF NOT EXISTS ss_rate (
  k TEXT PRIMARY KEY,
  n INTEGER,
  minute INTEGER
);
