CREATE TABLE IF NOT EXISTS alertas (
    id SERIAL PRIMARY KEY,
    event_id UUID UNIQUE NOT NULL,
    ip TEXT,
    status TEXT,
    risco INTEGER,
    score_final INTEGER,
    source_ip TEXT,
    threat_score INTEGER DEFAULT 0,
    severity TEXT DEFAULT 'LOW',
    mitre_id TEXT,
    mitre_name TEXT,
    mitre_tactic TEXT,
    human_summary TEXT,
    explanation TEXT,
    reasons JSONB,
    correlation_reasons JSONB,
    event_count INTEGER DEFAULT 0,
    replay_id TEXT,
    is_replay_event BOOLEAN DEFAULT FALSE,
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
    action_soc TEXT,
    simulated_block BOOLEAN DEFAULT FALSE,
    is_demo BOOLEAN DEFAULT FALSE,
    occurrence_count INTEGER DEFAULT 1,
    first_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    aggregated BOOLEAN DEFAULT FALSE,
    ports JSONB,
    services JSONB,
    event_types JSONB,
    raw_event JSONB
);

ALTER TABLE alertas ADD COLUMN IF NOT EXISTS event_id UUID UNIQUE;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS score_final INTEGER;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS source_ip TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS threat_score INTEGER DEFAULT 0;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS severity TEXT DEFAULT 'LOW';
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS mitre_id TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS mitre_name TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS mitre_tactic TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS human_summary TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS explanation TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS reasons JSONB;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS correlation_reasons JSONB;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS event_count INTEGER DEFAULT 0;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS replay_id TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS is_replay_event BOOLEAN DEFAULT FALSE;
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
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS action_soc TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS simulated_block BOOLEAN DEFAULT FALSE;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS is_demo BOOLEAN DEFAULT FALSE;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS occurrence_count INTEGER DEFAULT 1;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS first_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS aggregated BOOLEAN DEFAULT FALSE;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS ports JSONB;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS services JSONB;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS event_types JSONB;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS raw_event JSONB;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS mitre_techniques JSONB DEFAULT '[]'::jsonb;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS internal_rule_id TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS internal_rule_name TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS correlation_rule TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS response_playbook TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS detection_source TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS alert_type TEXT DEFAULT 'alert';
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS score_breakdown JSONB;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS score_explanation TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS target_host TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS target_ip TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS target_user TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS target_service TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS target_port INTEGER;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS target_container TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS target_application TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS environment TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS asset_owner TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS asset_criticality TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS business_impact TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS recommended_action TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS action_reason TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS execution_mode TEXT DEFAULT 'simulation';
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS execution_status TEXT DEFAULT 'not_executed';
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS execution_notes TEXT;

CREATE INDEX IF NOT EXISTS idx_alertas_ts ON alertas (ts DESC);
CREATE INDEX IF NOT EXISTS idx_alertas_ip ON alertas (ip);
CREATE INDEX IF NOT EXISTS idx_alertas_source_ip ON alertas (source_ip);
CREATE INDEX IF NOT EXISTS idx_alertas_replay_id ON alertas (replay_id);
CREATE INDEX IF NOT EXISTS idx_alertas_mitre_id ON alertas (mitre_id);
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

CREATE TABLE IF NOT EXISTS incident_overrides (
    incident_id TEXT PRIMARY KEY,
    status TEXT DEFAULT 'NEW',
    analyst_notes TEXT DEFAULT '',
    assigned_to TEXT DEFAULT '',
    soc_action TEXT DEFAULT 'investigação simulada',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE incident_overrides ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'NEW';
ALTER TABLE incident_overrides ADD COLUMN IF NOT EXISTS analyst_notes TEXT DEFAULT '';
ALTER TABLE incident_overrides ADD COLUMN IF NOT EXISTS assigned_to TEXT DEFAULT '';
ALTER TABLE incident_overrides ADD COLUMN IF NOT EXISTS soc_action TEXT DEFAULT 'investigação simulada';
ALTER TABLE incident_overrides ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE incident_overrides ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;

CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    incident_id TEXT UNIQUE NOT NULL,
    title TEXT,
    description TEXT,
    status TEXT DEFAULT 'NEW',
    severity TEXT DEFAULT 'LOW',
    max_score INTEGER DEFAULT 0,
    primary_source_ip TEXT,
    source_ips JSONB DEFAULT '[]'::jsonb,
    destination_ip TEXT,
    usernames JSONB DEFAULT '[]'::jsonb,
    services JSONB DEFAULT '[]'::jsonb,
    event_types JSONB DEFAULT '[]'::jsonb,
    mitre_techniques JSONB DEFAULT '[]'::jsonb,
    correlation_reasons JSONB DEFAULT '[]'::jsonb,
    replay_ids JSONB DEFAULT '[]'::jsonb,
    first_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    event_count INTEGER DEFAULT 0,
    human_summary TEXT,
    analyst_notes TEXT DEFAULT '',
    assigned_to TEXT DEFAULT '',
    soc_action TEXT DEFAULT 'investigação simulada',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE incidents ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS primary_source_ip TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS source_ips JSONB DEFAULT '[]'::jsonb;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS destination_ip TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS usernames JSONB DEFAULT '[]'::jsonb;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS services JSONB DEFAULT '[]'::jsonb;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS event_types JSONB DEFAULT '[]'::jsonb;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS mitre_techniques JSONB DEFAULT '[]'::jsonb;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS correlation_reasons JSONB DEFAULT '[]'::jsonb;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS replay_ids JSONB DEFAULT '[]'::jsonb;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS analyst_notes TEXT DEFAULT '';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS assigned_to TEXT DEFAULT '';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS soc_action TEXT DEFAULT 'investigação simulada';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS lifecycle_stage TEXT DEFAULT 'Detected';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS affected_assets JSONB DEFAULT '[]'::jsonb;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS evidence JSONB DEFAULT '[]'::jsonb;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS score_explanation TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS response_playbook TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS recommended_action TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS execution_mode TEXT DEFAULT 'simulation';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS execution_status TEXT DEFAULT 'not_executed';

CREATE TABLE IF NOT EXISTS incident_alerts (
    id SERIAL PRIMARY KEY,
    incident_id TEXT NOT NULL,
    alert_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (incident_id, alert_id)
);

CREATE TABLE IF NOT EXISTS incident_audit_log (
    id SERIAL PRIMARY KEY,
    incident_id TEXT NOT NULL,
    field_changed TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    changed_by TEXT DEFAULT 'system',
    changed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_incidents_incident_id ON incidents (incident_id);
CREATE INDEX IF NOT EXISTS idx_incidents_primary_source_ip ON incidents (primary_source_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);
CREATE INDEX IF NOT EXISTS idx_incidents_last_seen ON incidents (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_incident_alerts_incident_id ON incident_alerts (incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_alerts_alert_id ON incident_alerts (alert_id);
CREATE INDEX IF NOT EXISTS idx_incident_audit_incident_id ON incident_audit_log (incident_id);
