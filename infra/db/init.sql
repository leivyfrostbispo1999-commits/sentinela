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
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS tenant_id TEXT DEFAULT 'default';
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS correlation_id TEXT;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS idempotency_key TEXT;

CREATE INDEX IF NOT EXISTS idx_alertas_ts ON alertas (ts DESC);
CREATE INDEX IF NOT EXISTS idx_alertas_ip ON alertas (ip);
CREATE INDEX IF NOT EXISTS idx_alertas_source_ip ON alertas (source_ip);
CREATE INDEX IF NOT EXISTS idx_alertas_replay_id ON alertas (replay_id);
CREATE INDEX IF NOT EXISTS idx_alertas_mitre_id ON alertas (mitre_id);
CREATE INDEX IF NOT EXISTS idx_alertas_correlation_key ON alertas (correlation_key);
CREATE INDEX IF NOT EXISTS idx_alertas_tenant_ts ON alertas (tenant_id, ts DESC);

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
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS tenant_id TEXT DEFAULT 'default';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS idempotency_key TEXT;

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

ALTER TABLE alertas ADD COLUMN IF NOT EXISTS enrichment_geoip JSONB DEFAULT '{}'::jsonb;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS enrichment_threat JSONB DEFAULT '{}'::jsonb;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS flink_context JSONB DEFAULT '{}'::jsonb;

CREATE TABLE IF NOT EXISTS response_actions (
    id SERIAL PRIMARY KEY,
    action_id UUID UNIQUE NOT NULL,
    alert_id UUID NOT NULL,
    type TEXT NOT NULL,
    target TEXT,
    reason TEXT,
    mode TEXT DEFAULT 'simulated',
    status TEXT DEFAULT 'executed',
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    metadata_json JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_response_actions_alert_id ON response_actions (alert_id);
CREATE INDEX IF NOT EXISTS idx_response_actions_type ON response_actions (type);
CREATE INDEX IF NOT EXISTS idx_response_actions_ts ON response_actions (timestamp DESC);

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    plan_id TEXT DEFAULT 'free',
    api_key TEXT UNIQUE NOT NULL,
    status TEXT DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS plans (
    plan_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    max_eps INTEGER DEFAULT 10, -- Eventos por segundo
    max_alerts_per_day INTEGER DEFAULT 100,
    storage_retention_days INTEGER DEFAULT 7,
    price_monthly NUMERIC(10, 2) DEFAULT 0.00
);

CREATE TABLE IF NOT EXISTS billing_records (
    id SERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    billing_period TEXT NOT NULL, -- Ex: 2026-05
    event_count BIGINT DEFAULT 0,
    amount NUMERIC(10, 2) DEFAULT 0.00,
    status TEXT DEFAULT 'pending', -- pending, paid, overdue
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Inserir planos padrão
INSERT INTO plans (plan_id, name, max_eps, max_alerts_per_day, storage_retention_days, price_monthly)
VALUES 
    ('free', 'Plano Gratuito', 5, 50, 7, 0.00),
    ('pro', 'Plano Profissional', 100, 5000, 30, 499.00),
    ('enterprise', 'Plano Enterprise', 5000, 1000000, 365, 4999.00)
ON CONFLICT (plan_id) DO NOTHING;

-- Inserir tenant default
INSERT INTO tenants (tenant_id, name, plan_id, api_key, status)
VALUES ('default', 'Sentinela Demo Client', 'enterprise', 'sentinela-demo-api-key', 'active')
ON CONFLICT (tenant_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    tenant_id TEXT DEFAULT 'default',
    actor_user TEXT,
    actor_role TEXT,
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    correlation_id TEXT,
    source_ip TEXT,
    success BOOLEAN DEFAULT TRUE,
    metadata_json JSONB DEFAULT '{}'::jsonb
);

ALTER TABLE alertas ADD COLUMN IF NOT EXISTS campaign_id TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS campaign_id TEXT;
CREATE INDEX IF NOT EXISTS idx_alertas_campaign_id ON alertas (campaign_id);
CREATE INDEX IF NOT EXISTS idx_incidents_campaign_id ON incidents (campaign_id);

CREATE INDEX IF NOT EXISTS idx_incidents_incident_id ON incidents (incident_id);
CREATE INDEX IF NOT EXISTS idx_incidents_primary_source_ip ON incidents (primary_source_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);
CREATE INDEX IF NOT EXISTS idx_incidents_last_seen ON incidents (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_last_seen ON incidents (tenant_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_incident_alerts_incident_id ON incident_alerts (incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_alerts_alert_id ON incident_alerts (alert_id);
CREATE INDEX IF NOT EXISTS idx_incident_audit_incident_id ON incident_audit_log (incident_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_alertas_idempotency_key ON alertas (idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_idempotency_key ON incidents (idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_ts ON audit_logs (tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs (action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_type ON audit_logs (resource_type);
