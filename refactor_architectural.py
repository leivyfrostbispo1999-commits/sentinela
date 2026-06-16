import re

file_path = r"D:\sentinela\services\dashboard_web\index.html"
with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

# --- FASE 1, 2, 3, 10 & 11: RESTRUTURAÇÃO CSS COMPLETA ---
css_replacement = """
    /* ARQUITETURA ADAPTATIVA DE ALTA DENSIDADE */
    --space-1: 2px;
    --space-2: 4px;
    --space-3: 6px;
    --space-4: 8px;
    --space-6: 12px;
    --space-8: 16px;
}

* { box-sizing: border-box; }

body {
    margin: 0;
    min-height: 100vh;
    color: var(--text-primary);
    font-family: Inter, "Segoe UI", Arial, sans-serif;
    background: var(--bg);
    letter-spacing: -0.01em;
    line-height: 1.15;
    font-variant-numeric: tabular-nums;
    font-size: 0.72rem;
}

/* FASE 1: ELIMINAR ALTURAS FIXAS E BLACK HOLES */
.panel, .card {
    height: auto;
    min-height: unset;
    border: 1px solid var(--border-subtle);
    border-radius: 2px;
    background: var(--surface-primary);
    display: flex;
    flex-direction: column;
}

.shell { 
    width: 100%; 
    max-width: 100%; 
    margin: 0 auto; 
    padding: var(--space-2); 
    display: flex; 
    flex-direction: column; 
    gap: var(--space-2); 
}

/* FASE 9: COMMAND CENTER SUPERIOR COMPACTO */
header {
    display: flex;
    flex-direction: column;
    padding: var(--space-2) var(--space-3);
    background: var(--surface-secondary);
    border: 1px solid var(--border-subtle);
    border-radius: 2px;
    gap: var(--space-1);
}

.header-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    height: 28px;
}

.brand-panel h1 { font-size: 0.95rem; margin: 0; color: var(--text-primary); font-weight: 800; text-transform: uppercase; letter-spacing: 0.08em; }

.command-rail {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: var(--space-4);
    padding-top: var(--space-1);
    border-top: 1px solid var(--border-subtle);
    font-family: Consolas, monospace;
    font-size: 0.68rem;
}

.rail-item { display: flex; align-items: center; gap: var(--space-2); }
.rail-label { color: var(--text-secondary); text-transform: uppercase; font-weight: 700; font-size: 0.62rem; }
.rail-value { color: var(--text-primary); font-weight: 700; }

.toolbar { display: flex; gap: var(--space-2); align-items: center; }
.select, .button, .search, .login-input {
    min-height: 20px; height: 20px;
    border: 1px solid var(--border-subtle);
    border-radius: 2px;
    background: var(--surface-elevated);
    color: var(--text-primary);
    font-size: 0.68rem; font-weight: 600;
    padding: 0 var(--space-2);
}
.button { cursor: pointer; background: var(--surface-secondary); }
.button:hover { background: var(--surface-elevated); border-color: var(--border-strong); }
.button.demo { color: var(--red); border-color: rgba(239, 68, 68, 0.4); }

.mode-toggle { display: flex; height: 20px; border: 1px solid var(--border-subtle); border-radius: 2px; background: var(--surface-primary); }
.mode-button { border: 0; border-right: 1px solid var(--border-subtle); padding: 0 var(--space-3); background: transparent; color: var(--text-secondary); font-size: 0.62rem; font-weight: 700; cursor: pointer; text-transform: uppercase;}
.mode-button.active { background: var(--surface-elevated); color: var(--cyan); }

/* FASE 2: GRID OPERACIONAL REAL (12 Colunas) */
.grid { 
    display: grid; 
    grid-template-columns: repeat(12, minmax(0, 1fr)); 
    gap: var(--space-2); 
}

/* FASE 3: AUTO-SPAN DINÂMICO */
.span-3 { grid-column: span 3; }
.span-4 { grid-column: span 4; }
.span-6 { grid-column: span 6; }
.span-8 { grid-column: span 8; }
.span-9 { grid-column: span 9; }
.span-12 { grid-column: span 12; }

.panel-head { 
    display: flex; 
    justify-content: space-between; 
    align-items: center; 
    padding: var(--space-1) var(--space-3); 
    border-bottom: 1px solid var(--border-subtle); 
    background: var(--surface-secondary);
    min-height: 24px;
}
.panel-title { font-size: 0.65rem; font-weight: 800; text-transform: uppercase; color: var(--text-secondary); }

/* FASE 8: FEED TIPO TERMINAL SOC */
.feed-panel { grid-column: span 12; }
.feed { overflow: auto; max-height: 400px; background: #080b10; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 3px var(--space-2); border-bottom: 1px solid rgba(255,255,255,0.03); text-align: left; }
th { position: sticky; top: 0; background: var(--surface-secondary); color: var(--text-muted); font-size: 0.62rem; text-transform: uppercase; font-weight: 800; z-index: 10; border-bottom: 1px solid var(--border-strong); }
tbody { font-family: Consolas, monospace; font-size: 0.68rem; }
.time-sep { background: rgba(18, 24, 34, 0.8); color: var(--cyan); font-size: 0.62rem; font-weight: 800; padding: 2px 8px; position: sticky; top: 18px; z-index: 9; }

/* FASE 5: CADEIA MITRE HORIZONTAL REAL */
.mitre-flow { display: flex; align-items: center; gap: var(--space-1); flex-wrap: nowrap; overflow-x: auto; padding: var(--space-1) 0; scrollbar-width: none; }
.mitre-flow::-webkit-scrollbar { display: none; }
.mitre-step { background: var(--surface-elevated); border: 1px solid var(--border-strong); padding: 1px 6px; border-radius: 1px; font-size: 0.62rem; color: var(--text-primary); font-family: Consolas, monospace; font-weight: 800; white-space: nowrap; }
.mitre-arrow { color: var(--text-muted); font-size: 0.62rem; font-weight: 800; }

/* FASE 6 & 7: WORKSPACE INVESTIGATIVO */
.investigation-workspace {
    display: grid;
    grid-template-columns: repeat(12, 1fr);
    gap: var(--space-2);
    grid-column: span 12;
}
.workspace-left { grid-column: span 4; display: flex; flex-direction: column; gap: var(--space-2); }
.workspace-center { grid-column: span 5; display: flex; flex-direction: column; gap: var(--space-2); }
.workspace-right { grid-column: span 3; display: flex; flex-direction: column; gap: var(--space-2); }

.incident-overview { 
    display: grid; 
    grid-template-columns: 140px 1fr; 
    gap: var(--space-2); 
    padding: var(--space-2); 
    background: rgba(255,255,255,0.01);
}

/* FASE 7: TIMELINE FULL HEIGHT */
.timeline-compact { display: flex; flex-direction: column; overflow-y: auto; max-height: 600px; }
.timeline-compact-item { 
    display: grid; 
    grid-template-columns: 80px 1fr auto; 
    gap: var(--space-3); 
    padding: var(--space-1) var(--space-2); 
    border-left: 2px solid var(--cyan); 
    border-bottom: 1px solid rgba(255,255,255,0.03); 
    font-family: Consolas, monospace; 
    font-size: 0.68rem; 
}
.timeline-title { font-weight: 800; font-size: 0.68rem; }
.timeline-meta { display: flex; gap: var(--space-2); font-size: 0.62rem; }

.query-row { display: flex; gap: var(--space-2); padding: var(--space-1) var(--space-2); background: var(--surface-secondary); align-items: center; border-bottom: 1px solid var(--border-subtle); flex-wrap: wrap; }
.query-chip { height: 18px; padding: 0 5px; background: var(--surface-elevated); border: 1px solid var(--border-strong); color: var(--text-primary); font-size: 0.6rem; font-family: Consolas, monospace; font-weight: 800; }

.chart-box { height: 120px; padding: var(--space-1); }
.map-stage { height: 180px; position: relative; background: #080b10; overflow: hidden; }

.tag, .action { height: 14px; padding: 0 4px; border: 1px solid currentColor; font-size: 0.58rem; font-weight: 800; text-transform: uppercase; }

.critical-banner { padding: var(--space-1); font-size: 0.65rem; font-weight: 800; text-align: center; background: rgba(239, 68, 68, 0.15); color: var(--red); border: 1px solid var(--red); margin-bottom: var(--space-1); text-transform: uppercase; }

.rule-editor { height: 300px; padding: var(--space-2); }

@media (max-width: 1366px) {
    .workspace-left { grid-column: span 12; }
    .workspace-center { grid-column: span 12; }
    .workspace-right { grid-column: span 12; }
    .analytics-column { grid-column: span 12; }
    .map-column { grid-column: span 12; }
}
"""

# Apply the massive CSS reset
content = re.sub(r'/\* FASE 1: Spacing Scale.*?</style>', css_replacement + "\n</style>", content, flags=re.DOTALL)

# --- FASE 6: REORGANIZE HTML INTO ADAPTIVE WORKSPACE ---
# We will wrap key sections into the new investigation-workspace grid

body_pattern = r'<main class="shell">.*?</main>'
new_body = """<main class="shell">
    <header>
        <div class="header-top">
            <section class="brand-panel">
                <h1>SENTINELA SOC</h1>
            </section>
            <aside class="header-status">
                <div class="toolbar">
                    <button class="button focus-toggle" id="focusModeButton">FOCUS</button>
                    <select class="select" id="rangeSelect">
                        <option value="5m">5m</option>
                        <option value="1h" selected>1h</option>
                        <option value="24h">24h</option>
                    </select>
                    <div class="mode-toggle">
                        <button class="mode-button active" id="demoModeButton">DEMO</button>
                        <button class="mode-button" id="huntingModeButton">HUNT</button>
                    </div>
                    <button class="button demo" id="simulateAttackButton">SIMULAR</button>
                    <button class="button" id="refreshButton">SYNC</button>
                </div>
                <div class="session-line">
                    <strong id="apiStatus" class="status-pill degraded">API</strong>
                    <strong id="wsStatus" class="status-pill degraded">WS</strong>
                </div>
                <form class="login-bar" id="loginForm">
                    <input class="login-input" id="usernameInput" value="admin" style="width:60px;">
                    <input class="login-input" id="passwordInput" type="password" placeholder="senha" style="width:60px;">
                    <button class="button" id="loginButton">OK</button>
                </form>
            </aside>
        </div>
        <div class="command-rail">
            <div class="rail-item"><span class="rail-label">Threat:</span><span class="level low" id="threatLevel">LOW</span></div>
            <div class="rail-item"><span class="rail-label">Incid:</span><span class="rail-value" id="totalEventos">0</span></div>
            <div class="rail-item"><span class="rail-label">Crit:</span><span class="rail-value" id="eventosCriticos" style="color:var(--red)">0</span></div>
            <div class="rail-item"><span class="rail-label">IPs:</span><span class="rail-value" id="ipsUnicos">0</span></div>
            <div class="rail-item"><span class="rail-label">Risk:</span><span class="rail-value" id="bloqueios">0</span></div>
            <div class="rail-item"><span class="rail-label">MITRE:</span><span class="rail-value" id="tiMatches">N/D</span></div>
            <div class="rail-item"><span class="rail-label">RAM:</span><span class="rail-value" id="opsMemoryValue">--</span></div>
            <div class="rail-item"><span class="rail-label">CPU:</span><span class="rail-value" id="opsUptimeValue">--</span></div>
            <div style="flex:1;"></div>
            <input class="search" id="searchInput" placeholder="Filtro rápido..." style="width:180px;">
        </div>
    </header>

    <div class="critical-banner" id="criticalBanner">INCIDENTE CRÍTICO EM ANDAMENTO</div>

    <div class="investigation-workspace">
        <!-- COLUNA ESQUERDA: Fila e Contexto -->
        <div class="workspace-left">
            <section class="panel essential-panel" id="incidentsListPanel">
                <div class="panel-head">
                    <h2 class="panel-title">Fila de Incidentes</h2>
                    <div class="live" id="incidentsStatus">...</div>
                </div>
                <div class="toolbar" style="padding: 4px; border-bottom: 1px solid var(--border-subtle);">
                    <select class="select" id="incidentStatusFilter" style="flex:1;"><option value="all">Status</option></select>
                    <select class="select" id="incidentSeverityFilter" style="flex:1;"><option value="all">Severity</option></select>
                </div>
                <div class="rank-list" id="incidentsList" style="max-height: 200px; overflow-y: auto;"></div>
            </section>

            <section class="panel" id="ai-xdr-section">
                <div class="panel-head"><h2 class="panel-title">AI Anomaly & SOAR</h2></div>
                <div id="ai-scores-list" class="rank-list"></div>
                <div id="soar-status" class="rank-list"></div>
            </section>
        </div>

        <!-- COLUNA CENTRAL: Timeline Investigativa e Cadeia -->
        <div class="workspace-center">
            <section class="panel essential-panel" id="incidentPanel">
                <div class="panel-head">
                    <h2 class="panel-title">Workspace Investigativo</h2>
                    <div class="live" id="incidentStatus">LIVE</div>
                </div>
                <div class="incident-overview">
                    <div class="attacker-card">
                        <div class="rail-label">Atacante</div>
                        <div class="rail-value" id="attackerIp">--</div>
                    </div>
                    <div class="mitre-flow" id="attackChains">
                        <!-- Cadeia MITRE Horizontal renderizada aqui -->
                    </div>
                </div>
                <div class="timeline-compact" id="enterpriseTimeline" style="max-height: 450px;"></div>
            </section>
        </div>

        <!-- COLUNA DIREITA: Hunting & Analytics -->
        <div class="workspace-right">
            <section class="panel essential-panel" id="huntingConsole">
                <div class="panel-head"><h2 class="panel-title">Threat Hunting</h2></div>
                <div class="query-row">
                    <input class="search" id="huntingQuery" placeholder="Query..." style="flex:1;">
                    <button class="button" id="huntingSearchButton">HUNT</button>
                </div>
                <div class="rank-list" id="huntingResults" style="max-height: 150px; overflow-y: auto;"></div>
            </section>
            
            <section class="panel">
                <div class="panel-head"><h2 class="panel-title">Top Risk Targets</h2></div>
                <div class="rank-list" id="avgRiskList"></div>
            </section>

            <section class="panel map-column">
                <div class="panel-head"><h2 class="panel-title">Geo Threat Map</h2></div>
                <div class="map-stage" id="mapStage">
                    <svg class="world" viewBox="0 0 900 430" style="opacity:0.1;"><path d="M92 148l62-36 84 22 24 47-42 32-83-8-68-32z"></path></svg>
                    <div id="lines"></div>
                    <div id="points"></div>
                </div>
            </section>
        </div>
    </div>

    <!-- ÁREA INFERIOR: FEED COMPLETO E RULE STUDIO -->
    <div class="grid">
        <section class="panel feed-panel span-12">
            <div class="panel-head"><h2 class="panel-title">Operational Alert Stream</h2></div>
            <div class="feed">
                <table>
                    <thead>
                        <tr>
                            <th>TIME</th>
                            <th>SOURCE &rarr; TARGET</th>
                            <th>SEV</th>
                            <th>RISK</th>
                            <th>MITRE / RULE</th>
                            <th>PLAYBOOK</th>
                        </tr>
                    </thead>
                    <tbody id="feedBody"></tbody>
                </table>
            </div>
        </section>

        <section class="panel span-6 essential-panel" id="ruleStudio">
            <div class="panel-head"><h2 class="panel-title">Rule Studio</h2></div>
            <div class="rule-editor">
                <div id="monacoEditor"></div>
                <div class="toolbar" style="margin-top:4px;">
                    <button class="button" id="validateRuleButton">Validar</button>
                    <button class="button demo" id="saveRuleButton">Salvar</button>
                </div>
            </div>
        </section>

        <section class="panel span-6" id="adminUsersPanel">
            <div class="panel-head"><h2 class="panel-title">RBAC & Users</h2></div>
            <div class="rank-list" id="usersList" style="max-height: 250px; overflow-y: auto;"></div>
        </section>
    </div>
</main>"""

content = re.sub(body_pattern, new_body, content, flags=re.DOTALL)

# --- FASE 12: OPTIMIZE JS RENDERING FOR DENSITY ---
# We need to make sure renderFeed and other lists don't have too much empty space

render_feed_pattern = r'function renderFeed\(alerts\) \{.*?\}'
new_render_feed = """function renderFeed(alerts) {
    const tbody = el('feedBody');
    if (!alerts.length) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:20px; color:var(--text-muted)">Aguardando eventos...</td></tr>';
        return;
    }
    let lastTime = '';
    let html = '';
    alerts.slice(0, 40).forEach(a => {
        const dateObj = new Date(a.ts || a.timestamp);
        const timeStr = dateObj.toLocaleTimeString('pt-BR', {hour: '2-digit', minute: '2-digit'});
        if (timeStr !== lastTime) {
            html += `<tr><td colspan="6" class="time-sep">${timeStr}</td></tr>`;
            lastTime = timeStr;
        }
        const sev = severity(a);
        const color = getSeverityColor(sev);
        const [action, actionClass] = socAction(a);
        html += `
            <tr class="clickable-row" data-alert-id="${esc(a.id)}">
                <td class="mono" style="border-left:2px solid ${color}">${esc(dateObj.toLocaleTimeString('pt-BR'))}</td>
                <td class="mono">${esc(a.source_ip || a.ip)} &rarr; ${esc(a.target_host || 'local')}</td>
                <td><span class="tag ${sev}">${esc(translateSeverity(sev))}</span></td>
                <td class="mono" style="color:${color}">${risk(a)}</td>
                <td class="mono">${esc(a.mitre_id || 'N/D')}</td>
                <td><span class="action ${actionClass}">${esc(action)}</span></td>
            </tr>
        `;
    });
    tbody.innerHTML = html;
}"""

content = re.sub(render_feed_pattern, new_render_feed, content, flags=re.DOTALL)

with open(file_path, "w", encoding="utf-8") as f:
    f.write(content)
print("Arquitetura adaptativa implementada.")
