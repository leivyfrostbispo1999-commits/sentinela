CREATE TABLE IF NOT EXISTS alertas (
    id SERIAL PRIMARY KEY,
    event_id UUID UNIQUE NOT NULL,
    ip TEXT,
    status TEXT,
    risco INTEGER,
    score_final INTEGER,
    ts TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    "timestamp" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    service TEXT,
    port INTEGER,
    event_type TEXT,
    ip_event_count INTEGER DEFAULT 0,
    risk_reasons JSONB,
    threat_intel_match BOOLEAN DEFAULT FALSE,
    threat_category TEXT,
    threat_description TEXT,
    threat_reputation_score INTEGER,
    threat_source TEXT,
    correlation_window_seconds INTEGER,
    correlation_key TEXT,
    correlation_reason TEXT,
    auto_response TEXT DEFAULT 'none',
    simulated_block BOOLEAN DEFAULT FALSE,
    raw_event JSONB
);

ALTER TABLE alertas ADD COLUMN IF NOT EXISTS event_id UUID UNIQUE;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS score_final INTEGER;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS service TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS port INTEGER;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS event_type TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS ip_event_count INTEGER DEFAULT 0;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS risk_reasons JSONB;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS threat_intel_match BOOLEAN DEFAULT FALSE;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS threat_category TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS threat_description TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS threat_reputation_score INTEGER;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS threat_source TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS correlation_window_seconds INTEGER;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS correlation_key TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS correlation_reason TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS auto_response TEXT DEFAULT 'none';
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS simulated_block BOOLEAN DEFAULT FALSE;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS raw_event JSONB;

CREATE INDEX IF NOT EXISTS idx_alertas_ts ON alertas (ts DESC);
CREATE INDEX IF NOT EXISTS idx_alertas_ip ON alertas (ip);
CREATE INDEX IF NOT EXISTS idx_alertas_correlation_key ON alertas (correlation_key);

CREATE TABLE IF NOT EXISTS blacklist (
    ip TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    first_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    offense_count INTEGER DEFAULT 1,
    active BOOLEAN DEFAULT TRUE,
    response_mode TEXT DEFAULT 'simulated_block'
);
