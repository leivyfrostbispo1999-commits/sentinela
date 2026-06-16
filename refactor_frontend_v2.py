import re

file_path = r"D:\sentinela\services\dashboard_web\index.html"
with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

# 1. Update CSS Tokens & Grid layout
css_replacement = """
    /* FASE 1: Spacing Scale & FASE 3: Densidade Operacional */
    --space-1: 2px;
    --space-2: 4px;
    --space-3: 6px;
    --space-4: 10px;
    --space-6: 16px;
    --space-8: 24px;
    
    --shadow-sm: 0 1px 2px rgba(0,0,0,0.4);
    --shadow-md: 0 4px 8px rgba(0,0,0,0.5);
}

* { box-sizing: border-box; }

body {
    margin: 0;
    min-height: 100vh;
    color: var(--text-primary);
    font-family: Inter, "Segoe UI", Arial, sans-serif;
    background: var(--bg);
    letter-spacing: -0.015em;
    line-height: 1.25;
    font-variant-numeric: tabular-nums;
    font-size: 0.75rem;
}

.shell { width: 100%; max-width: 2560px; margin: 0 auto; padding: var(--space-4); display: flex; flex-direction: column; gap: var(--space-4); }

/* FASE 2 & FASE 11: Superfícies Contínuas e Layout Macro */
.panel, .card {
    border: 1px solid var(--border-subtle);
    border-radius: 3px;
    background: var(--surface-primary);
    box-shadow: none;
}

/* FASE 9: COMMAND CENTER SUPERIOR */
header {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    padding: var(--space-3) var(--space-4);
    background: var(--surface-secondary);
    border: 1px solid var(--border-subtle);
    border-radius: 3px;
}

.header-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
}

.brand-panel { display: flex; align-items: center; gap: var(--space-4); }
.brand-panel p, .brand-kicker { display: none; }
h1 { font-size: 1.1rem; margin: 0; color: var(--text-primary); font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }

.header-status {
    display: flex;
    align-items: center;
    gap: var(--space-4);
}

.command-rail {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: var(--space-4);
    padding-top: var(--space-3);
    border-top: 1px solid var(--border-subtle);
    font-family: Consolas, monospace;
    font-size: 0.7rem;
}

.rail-item {
    display: flex;
    align-items: center;
    gap: var(--space-2);
}
.rail-label { color: var(--text-secondary); text-transform: uppercase; font-weight: 600; }
.rail-value { color: var(--text-primary); font-weight: 700; }

h1, h2, h3, p { margin: 0; }
h2.panel-title { font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.02em; color: var(--text-secondary); }
.subtitle, .muted { color: var(--text-muted); font-size: 0.7rem; }

.toolbar { display: flex; gap: var(--space-2); align-items: center; flex-wrap: wrap; }
.select, .button, .search, .login-input {
    min-height: 24px; height: 24px;
    border: 1px solid var(--border-subtle);
    border-radius: 2px;
    background: var(--surface-elevated);
    color: var(--text-primary);
    font-size: 0.7rem; font-weight: 500;
    padding: 0 var(--space-2);
}
.button { cursor: pointer; color: var(--text-primary); background: var(--surface-secondary); font-weight: 600; }
.button:hover { background: var(--surface-elevated); border-color: var(--border-strong); }
.button.demo { color: var(--red); border-color: rgba(239, 68, 68, 0.3); }

.mode-toggle { display: flex; height: 24px; border: 1px solid var(--border-subtle); border-radius: 2px; background: var(--surface-primary); }
.mode-button { border: 0; border-right: 1px solid var(--border-subtle); padding: 0 var(--space-3); background: transparent; color: var(--text-secondary); font-size: 0.65rem; font-weight: 700; cursor: pointer; text-transform: uppercase;}
.mode-button:last-child { border-right: 0; }
.mode-button.active { background: var(--surface-elevated); color: var(--cyan); }

.login-bar { display: flex; gap: var(--space-2); }
.session-line { display: flex; align-items: center; gap: var(--space-3); color: var(--text-secondary); font-family: Consolas, monospace; font-size: 0.65rem; }

.status-pill { display: inline-flex; align-items: center; gap: 4px; font-size: 0.65rem; color: var(--text-secondary); text-transform: uppercase; font-weight: 700; }
.status-pill::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.status-pill.online::before { color: var(--green); }
.status-pill.degraded::before { color: var(--yellow); }
.status-pill.critical::before { color: var(--red); }

.level { font-family: Consolas, monospace; font-size: 0.7rem; font-weight: 700; padding: 2px 4px; border-radius: 2px; background: var(--surface-elevated); }
.level.low { color: var(--severity-low); }
.level.medium { color: var(--severity-medium); }
.level.high { color: var(--severity-high); }
.level.critical { color: var(--severity-critical); }

.panel-head { display: flex; justify-content: space-between; align-items: center; padding: var(--space-2) var(--space-3); border-bottom: 1px solid var(--border-subtle); background: var(--surface-secondary); }

/* FASE 8: Feed Operacional Enterprise */
.feed-panel { display: flex; flex-direction: column; grid-column: span 12; }
.feed { overflow-x: auto; flex: 1; max-height: 500px; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 4px var(--space-2); border-bottom: 1px solid var(--border-subtle); text-align: left; vertical-align: middle; }
th { position: sticky; top: 0; background: var(--surface-secondary); color: var(--text-secondary); font-family: Inter, sans-serif; font-size: 0.65rem; text-transform: uppercase; font-weight: 700; z-index: 10; border-bottom: 1px solid var(--border-strong); }
tbody { font-family: Consolas, monospace; font-size: 0.7rem; }
.clickable-row { cursor: pointer; transition: background 50ms; }
.clickable-row:hover { background: var(--surface-elevated); }
.time-sep { background: var(--surface-primary); color: var(--text-muted); font-size: 0.65rem; font-weight: 700; padding: 2px 8px; border-bottom: 1px solid var(--border-subtle); position: sticky; top: 21px; z-index: 9; }

.tag, .action, .severity-badge { display: inline-flex; align-items: center; height: 16px; padding: 0 4px; border: 1px solid currentColor; border-radius: 2px; font-size: 0.6rem; font-weight: 700; text-transform: uppercase; background: transparent; }
.tag.low, .action.monitorado { color: var(--green); border-color: rgba(16, 185, 129, 0.3); }
.tag.medium, .action.investigando { color: var(--yellow); border-color: rgba(245, 158, 11, 0.3); }
.tag.high { color: var(--orange); border-color: rgba(249, 115, 22, 0.3); }
.tag.critical, .action.bloqueio { color: var(--red); border-color: rgba(239, 68, 68, 0.3); }

/* Grid Sistema 12 colunas */
.grid { display: grid; grid-template-columns: repeat(12, 1fr); gap: var(--space-4); }

.analytics-column { grid-column: span 3; display: flex; flex-direction: column; gap: var(--space-4); }
.map-column { grid-column: span 9; display: flex; flex-direction: column; }
.analytics-grid { display: grid; grid-template-columns: 1fr; gap: var(--space-4); }

/* FASE 4 & 5: Timeline Investigativa Full-Width */
.incident-panel { grid-column: span 12; display: flex; flex-direction: column; }
.incident-overview { display: grid; grid-template-columns: repeat(4, 1fr); gap: var(--space-3); padding: var(--space-3); }

.timeline-compact { display: flex; flex-direction: column; gap: 0; padding: 0; }
.timeline-compact-item { display: grid; grid-template-columns: 100px 1fr auto; gap: var(--space-4); align-items: center; padding: var(--space-2) var(--space-3); border-left: 2px solid var(--cyan); border-bottom: 1px solid var(--border-subtle); background: transparent; font-family: Consolas, monospace; font-size: 0.7rem; }
.timeline-compact-item:hover { background: var(--surface-elevated); }
.timeline-compact-item.critical { border-left-color: var(--red); background: rgba(239, 68, 68, 0.05); }
.timeline-time { color: var(--text-secondary); font-size: 0.65rem; }
.timeline-title { font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: var(--space-2); }
.timeline-desc { color: var(--text-secondary); margin-top: 2px; }
.timeline-meta { display: flex; gap: var(--space-2); }

.cluster-count { display: inline-flex; align-items: center; justify-content: center; background: var(--surface-secondary); color: var(--cyan); border-radius: 2px; padding: 0 4px; font-size: 0.6rem; border: 1px solid var(--border-subtle); }

.rule-editor { display: flex; flex-direction: column; gap: var(--space-2); padding: var(--space-3); height: 350px; }
#monacoEditor { flex: 1; border: 1px solid var(--border-subtle); border-radius: 2px; }
#ruleEditor { display: none; }
.mitre-chip { display: inline-flex; align-items: center; height: 18px; padding: 0 6px; border: 1px solid var(--border-subtle); border-radius: 2px; background: var(--surface-secondary); color: var(--purple); font-family: Consolas, monospace; font-size: 0.6rem; font-weight: 700; text-transform: uppercase; }

/* FASE 7: Hunting Chips */
.query-row { display: flex; gap: var(--space-3); padding: var(--space-2) var(--space-3); background: var(--surface-secondary); align-items: center; border-bottom: 1px solid var(--border-subtle); flex-wrap: wrap; }
.query-chip { display: inline-flex; align-items: center; gap: 4px; height: 20px; padding: 0 6px; border-radius: 2px; background: var(--surface-elevated); border: 1px solid var(--border-strong); color: var(--text-primary); font-size: 0.65rem; cursor: pointer; font-family: Consolas, monospace; }

/* FASE 5: Attack Chain Horizontal Flow */
.mitre-flow { display: flex; align-items: center; gap: var(--space-2); flex-wrap: wrap; margin-top: var(--space-2); }
.mitre-step { background: var(--surface-secondary); border: 1px solid var(--border-subtle); padding: 2px 6px; border-radius: 2px; font-size: 0.65rem; color: var(--text-primary); font-family: Consolas, monospace; font-weight: 700; text-transform: uppercase; }
.mitre-arrow { color: var(--text-muted); font-size: 0.7rem; }

.chart-box { height: 150px; padding: var(--space-2); }
.map-stage { height: 200px; margin: var(--space-2); background: var(--surface-secondary); border: 1px solid var(--border-subtle); border-radius: 2px; overflow: hidden; position: relative; }

.rank-list { display: flex; flex-direction: column; padding: 0; gap: 0; }
.rank-item { display: flex; justify-content: space-between; align-items: center; padding: 4px var(--space-3); background: transparent; border-bottom: 1px solid var(--border-subtle); font-family: Consolas, monospace; font-size: 0.7rem; }
.rank-item:hover { background: var(--surface-elevated); }
.empty-state { padding: var(--space-4); text-align: center; color: var(--text-muted); font-size: 0.7rem; font-family: Consolas, monospace; }

.critical-banner { display: none; padding: var(--space-2); text-align: center; background: rgba(239, 68, 68, 0.1); border: 1px solid var(--red); color: var(--red); font-weight: 700; font-size: 0.75rem; margin-bottom: var(--space-3); border-radius: 2px; text-transform: uppercase; letter-spacing: 0.05em; }
.critical-banner.show { display: block; }

.product-grid { display: grid; grid-template-columns: repeat(12, 1fr); gap: var(--space-4); margin-bottom: var(--space-4); }
.product-panel { display: flex; flex-direction: column; grid-column: span 6; }
.product-panel.full { grid-column: span 12; }

*::-webkit-scrollbar { width: 4px; height: 4px; }
*::-webkit-scrollbar-track { background: var(--surface-primary); }
*::-webkit-scrollbar-thumb { background: var(--surface-elevated); border-radius: 2px; }
*::-webkit-scrollbar-thumb:hover { background: var(--border-strong); }

@media (max-width: 1400px) {
    .analytics-column { grid-column: span 4; }
    .map-column { grid-column: span 8; }
    .product-panel { grid-column: span 12; }
}
"""

content = re.sub(r'--space-1: 4px;.*?@media \(max-width: 1200px\) \{.*?\n\}', css_replacement, content, flags=re.DOTALL)

# 2. Modify Header to Command Rail (Fase 9)
header_regex = r'<header>.*?</header>'
new_header = """<header>
    <div class="header-top">
        <section class="brand-panel">
            <h1>SENTINELA SOC</h1>
        </section>
        <aside class="header-status">
            <div class="toolbar">
                <button class="button focus-toggle" id="focusModeButton" type="button">FOCUS</button>
                <select class="select" id="rangeSelect" aria-label="Filtro de tempo">
                    <option value="5m">5m</option>
                    <option value="15m">15m</option>
                    <option value="1h" selected>1h</option>
                    <option value="24h">24h</option>
                </select>
                <div class="mode-toggle">
                    <button class="mode-button active" id="demoModeButton" type="button">DEMO</button>
                    <button class="mode-button" id="historyModeButton" type="button">HISTÓRICO</button>
                    <button class="mode-button" id="huntingModeButton" type="button">HUNTING</button>
                    <button class="mode-button" id="rulesModeButton" type="button">REGRAS</button>
                </div>
                <button class="button demo" id="simulateAttackButton" type="button">SIMULAR</button>
                <button class="button" id="refreshButton" type="button">SYNC</button>
            </div>
            <div class="session-line">
                <span id="sessionInfo">Sessão local</span>
                <strong id="apiStatus" class="status-pill degraded">API verificando</strong>
                <strong id="wsStatus" class="status-pill degraded">WS conectando</strong>
            </div>
            <form class="login-bar" id="loginForm">
                <input class="login-input" id="usernameInput" autocomplete="username" value="admin">
                <input class="login-input" id="passwordInput" type="password" placeholder="senha">
                <button class="button" id="loginButton" type="submit">LOGIN</button>
                <button class="button" id="logoutButton" type="button">SAIR</button>
            </form>
        </aside>
    </div>
    <div class="command-rail">
        <div class="rail-item"><span class="rail-label">Threat Level:</span><span class="level low" id="threatLevel">BAIXO</span></div>
        <div class="rail-item"><span class="rail-label">Incidents:</span><span class="rail-value" id="totalEventos">0</span></div>
        <div class="rail-item"><span class="rail-label">Critical:</span><span class="rail-value" id="eventosCriticos" style="color:var(--red)">0</span></div>
        <div class="rail-item"><span class="rail-label">Unique IPs:</span><span class="rail-value" id="ipsUnicos">0</span></div>
        <div class="rail-item"><span class="rail-label">Max Score:</span><span class="rail-value" id="bloqueios">0</span></div>
        <div class="rail-item"><span class="rail-label">Top MITRE:</span><span class="rail-value" id="tiMatches">N/D</span></div>
        <div class="rail-item"><span class="rail-label">Last Replay:</span><span class="rail-value" id="lastReplayCard">N/D</span></div>
        <div class="rail-item"><span class="rail-label">RAM:</span><span class="rail-value" id="opsMemoryValue">sincronizando</span></div>
        <div class="rail-item"><span class="rail-label">Uptime:</span><span class="rail-value" id="opsUptimeValue">sincronizando</span></div>
        <div class="rail-item"><span class="rail-label">Disk:</span><span class="rail-value" id="opsDiskValue">sincronizando</span></div>
        <div class="rail-item"><span class="rail-label">Sync:</span><span class="rail-value muted" id="lastUpdate">Inicializando</span></div>
        <div style="flex:1;"></div>
        <div class="toolbar" style="margin:0;">
            <input class="search" id="searchInput" type="search" placeholder="Buscar IP, MITRE, Status..." style="width: 250px;">
            <select class="select" id="severityFilter">
                <option value="all">Todas Severidades</option>
                <option value="critical">Crítico</option>
                <option value="high">Alto</option>
                <option value="medium">Médio</option>
                <option value="low">Baixo</option>
            </select>
        </div>
    </div>
</header>"""

content = re.sub(header_regex, new_header, content, flags=re.DOTALL)

# Remove the old .cards and .ops-strip sections since they are now in the command rail
content = re.sub(r'<section class="cards">.*?</section>', '', content, flags=re.DOTALL)
content = re.sub(r'<section class="ops-strip" aria-label="Observabilidade operacional">.*?</section>', '', content, flags=re.DOTALL)

# 3. Grid Adjustments & Attack Chain
# Make incident list full width
content = content.replace('class="panel" id="incidentsListPanel"', 'class="panel product-panel full" id="incidentsListPanel"')

# Ensure Timeline is full width in product-grid
content = content.replace('<section class="panel product-panel">\n                <div class="panel-head">\n                    <div>\n                        <h2 class="panel-title">Timeline Operacional</h2>', '<section class="panel product-panel full">\n                <div class="panel-head">\n                    <div>\n                        <h2 class="panel-title">Timeline Operacional</h2>')

# 4. Modify correlation rendering (Fase 5 - Attack Chain)
js_chain_replace = r"<div>\$\{\(chain\.mitre_sequence \|\| \[\]\)\.map\(m => `<span class=\"tag medium\">\$\{esc\(m\)\}<\/span>`\)\.join\(' '\)\}<\/div>"
new_js_chain = r"""<div class="mitre-flow">${(chain.mitre_sequence || []).map(m => `<div class="mitre-step">${esc(m)}</div>`).join('<div class="mitre-arrow">&rarr;</div>')}</div>"""
content = re.sub(js_chain_replace, new_js_chain, content)

# 5. Fix Focus mode JS to target panels better
focus_js_replace = r"\['incidentsListPanel', 'productConsole', 'huntingConsole', 'ruleStudio'\]\.forEach\(id => \{\s*const el = document\.getElementById\(id\);\s*if\(el\) el\.classList\.add\('essential-panel'\);\s*\}\);"
new_focus_js = r"['incidentPanel', 'incidentsListPanel', 'productConsole', 'huntingConsole', 'ruleStudio'].forEach(id => { const el = document.getElementById(id); if(el) el.classList.add('essential-panel'); });"
content = re.sub(focus_js_replace, new_focus_js, content)

# 6. Hunting chips (Fase 7)
hunting_html_replace = r'<div class="query-row">\s*<input class="search" id="huntingQuery" type="search" placeholder="IOC, técnica, usuário ou evidência">\s*<input class="search" id="huntingIp" type="search" placeholder="IP">\s*<input class="search" id="huntingMitre" type="search" placeholder="MITRE">\s*<button class="button" id="huntingSearchButton" type="button">Buscar</button>\s*</div>'
new_hunting_html = r"""<div class="query-row">
                    <input class="search" id="huntingQuery" type="search" placeholder="KQL-like query (e.g. status: CRITICAL)" style="flex:1;">
                    <div class="query-chip">host: *</div>
                    <div class="query-chip">severity: high OR critical</div>
                    <input class="search" id="huntingIp" type="search" placeholder="IP" style="width: 100px;">
                    <input class="search" id="huntingMitre" type="search" placeholder="MITRE" style="width: 80px;">
                    <button class="button" id="huntingSearchButton" type="button">Run Hunt</button>
                </div>"""
content = re.sub(hunting_html_replace, new_hunting_html, content)

with open(file_path, "w", encoding="utf-8") as f:
    f.write(content)
