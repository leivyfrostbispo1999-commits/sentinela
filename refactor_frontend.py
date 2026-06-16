import os

file_path = r"D:\sentinela\services\dashboard_web\index.html"

with open(file_path, "r", encoding="utf-8") as f:
    html_content = f.read()

# 1. Replace the entire CSS
css_start = html_content.find("<style>")
css_end = html_content.find("</style>") + 8

new_css = """<style>
/* FASE 10: DESIGN SYSTEM REAL (Tokens) */
:root {
    --bg: #0b0f15;
    --surface-primary: #121822;
    --surface-secondary: #1a222e;
    --surface-elevated: #222b38;
    --surface-overlay: rgba(18, 24, 34, 0.95);
    
    --border-subtle: rgba(112, 213, 255, 0.12);
    --border-strong: rgba(112, 213, 255, 0.25);
    --border-focus: rgba(112, 213, 255, 0.5);
    
    --text-primary: #ecf6ff;
    --text-secondary: #92aabe;
    --text-muted: #64748b;
    
    --cyan: #38bdf8;
    --cyan-soft: #7dd3fc;
    --green: #10b981;
    --yellow: #f59e0b;
    --orange: #f97316;
    --red: #ef4444;
    --purple: #8b5cf6;
    
    --severity-critical: var(--red);
    --severity-high: var(--orange);
    --severity-medium: var(--yellow);
    --severity-low: var(--green);

    /* FASE 1: Spacing Scale */
    --space-1: 4px;
    --space-2: 8px;
    --space-3: 12px;
    --space-4: 16px;
    --space-6: 24px;
    --space-8: 32px;
    
    --shadow-sm: 0 1px 3px rgba(0,0,0,0.3);
    --shadow-md: 0 4px 12px rgba(0,0,0,0.4);
}

* { box-sizing: border-box; }

body {
    margin: 0;
    min-height: 100vh;
    color: var(--text-primary);
    font-family: Inter, "Segoe UI", Arial, sans-serif;
    background: var(--bg);
    /* FASE 9: Micro-tipografia */
    letter-spacing: -0.01em;
    line-height: 1.4;
    font-variant-numeric: tabular-nums;
}

body.focus-mode .panel:not(.essential-panel) {
    display: none !important;
}

.shell { width: min(1800px, 100%); margin: 0 auto; padding: var(--space-3); }

/* FASE 2: Superfícies Contínuas (Sem glows) */
.panel, .card {
    border: 1px solid var(--border-subtle);
    border-radius: 4px;
    background: var(--surface-primary);
    box-shadow: var(--shadow-sm);
}

/* FASE 3: Command Bar Enterprise */
header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: var(--space-2) var(--space-4);
    background: var(--surface-secondary);
    border: 1px solid var(--border-subtle);
    border-radius: 4px;
    margin-bottom: var(--space-3);
    height: 52px;
}

.brand-panel { display: flex; align-items: center; gap: var(--space-3); }
.brand-panel p, .brand-kicker { display: none; }
h1 { font-size: 1.2rem; margin: 0; color: var(--text-primary); font-weight: 600; text-shadow: none; letter-spacing: 0.05em; }

.header-status {
    display: flex;
    align-items: center;
    gap: var(--space-4);
}

h1, h2, h3, p { margin: 0; }
h2.panel-title { font-size: 0.8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.02em; color: var(--text-secondary); }
.subtitle, .muted { color: var(--text-secondary); font-size: 0.75rem; }

/* FASE 1: Redução de alturas */
.toolbar { display: flex; gap: var(--space-2); align-items: center; flex-wrap: wrap; }
.select, .button, .search, .login-input {
    min-height: 28px; height: 28px;
    border: 1px solid var(--border-subtle);
    border-radius: 3px;
    background: var(--surface-elevated);
    color: var(--text-primary);
    font-size: 0.75rem; font-weight: 500;
    transition: none;
}
.select { padding: 0 var(--space-6) 0 var(--space-2); }
.search, .login-input { padding: 0 var(--space-2); }
.button { padding: 0 var(--space-3); cursor: pointer; color: var(--text-primary); background: var(--surface-secondary); }
.button:hover { background: var(--surface-elevated); border-color: var(--border-strong); }
.button.demo { color: var(--red); border-color: rgba(239, 68, 68, 0.3); }

.mode-toggle { display: flex; height: 28px; border: 1px solid var(--border-subtle); border-radius: 3px; background: var(--surface-primary); }
.mode-button { border: 0; border-right: 1px solid var(--border-subtle); padding: 0 var(--space-2); background: transparent; color: var(--text-secondary); font-size: 0.7rem; font-weight: 600; cursor: pointer; }
.mode-button:last-child { border-right: 0; }
.mode-button.active { background: var(--surface-elevated); color: var(--cyan); }

.login-bar { display: flex; gap: var(--space-2); }

.session-line { display: flex; align-items: center; gap: var(--space-3); color: var(--text-secondary); font-family: Consolas, monospace; font-size: 0.7rem; }

/* FASE 4: Status Indicators */
.status-pill { display: inline-flex; align-items: center; gap: 4px; font-size: 0.7rem; color: var(--text-secondary); }
.status-pill::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.status-pill.online::before { color: var(--green); }
.status-pill.degraded::before { color: var(--yellow); }
.status-pill.critical::before { color: var(--red); }

.level { font-family: Consolas, monospace; font-size: 0.75rem; font-weight: 600; padding: 2px 6px; border-radius: 3px; background: var(--surface-elevated); }
.level.low { color: var(--severity-low); }
.level.medium { color: var(--severity-medium); }
.level.high { color: var(--severity-high); }
.level.critical { color: var(--severity-critical); }

/* KPI Cards e Ops Strip integrados no Command Rail / Topo */
.cards { display: flex; gap: var(--space-2); margin-bottom: var(--space-3); }
.card { flex: 1; padding: var(--space-2) var(--space-3); display: flex; flex-direction: column; justify-content: center; min-height: 52px; border-radius: 3px; }
.card-label { color: var(--text-secondary); font-size: 0.65rem; font-weight: 600; text-transform: uppercase; display: flex; align-items: center; gap: var(--space-1); }
.card-label::before { display: none; }
.card-value { margin-top: 4px; color: var(--text-primary); font-family: Consolas, monospace; font-size: 1.15rem; font-weight: 600; text-shadow: none; }

.ops-strip { display: flex; gap: var(--space-4); margin-bottom: var(--space-3); padding: var(--space-2) var(--space-4); background: var(--surface-secondary); border: 1px solid var(--border-subtle); border-radius: 3px; font-size: 0.7rem; align-items: center; flex-wrap: wrap;}
.ops-item { display: flex; align-items: center; gap: var(--space-2); font-family: Consolas, monospace; }
.ops-item::before { display: none; }
.ops-label { color: var(--text-secondary); font-size: 0.65rem; font-weight: 600; text-transform: uppercase; }
.ops-value { color: var(--text-primary); font-size: 0.75rem; font-weight: 400; }
.ops-item.ok .ops-value { color: var(--green); }
.ops-item.warn .ops-value { color: var(--yellow); }
.ops-item.fail .ops-value { color: var(--red); }

/* Painéis Contínuos */
.panel-head { display: flex; justify-content: space-between; align-items: center; padding: var(--space-2) var(--space-3); border-bottom: 1px solid var(--border-subtle); background: var(--surface-secondary); }

/* FASE 4: Feed Operacional Enterprise */
.feed-panel { display: flex; flex-direction: column; }
.feed { overflow-x: auto; flex: 1; max-height: 600px; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 6px var(--space-2); border-bottom: 1px solid var(--border-subtle); text-align: left; vertical-align: middle; }
th { position: sticky; top: 0; background: var(--surface-secondary); color: var(--text-secondary); font-family: Inter, sans-serif; font-size: 0.65rem; text-transform: uppercase; font-weight: 600; z-index: 10; border-bottom: 2px solid var(--border-strong); }
tbody { font-family: Consolas, monospace; font-size: 0.75rem; }
.clickable-row { cursor: pointer; transition: background 100ms; }
.clickable-row:hover { background: var(--surface-elevated); }
.time-sep { background: var(--surface-primary); color: var(--text-muted); font-size: 0.65rem; font-weight: 600; padding: 4px 8px; border-bottom: 1px solid var(--border-subtle); position: sticky; top: 25px; z-index: 9; }

/* Badges e Tags */
.tag, .action, .severity-badge { display: inline-flex; align-items: center; height: 18px; padding: 0 6px; border: 1px solid currentColor; border-radius: 2px; font-size: 0.6rem; font-weight: 600; text-transform: uppercase; background: transparent; }
.tag.low, .action.monitorado { color: var(--green); border-color: rgba(16, 185, 129, 0.4); }
.tag.medium, .action.investigando { color: var(--yellow); border-color: rgba(245, 158, 11, 0.4); }
.tag.high { color: var(--orange); border-color: rgba(249, 115, 22, 0.4); }
.tag.critical, .action.bloqueio { color: var(--red); border-color: rgba(239, 68, 68, 0.4); }

.grid { display: grid; grid-template-columns: 1fr 400px; grid-template-areas: "analytics map" "feed feed"; gap: var(--space-3); margin-bottom: var(--space-3); }

/* FASE 5: Timeline Operacional / Investigativa */
.timeline-compact { display: flex; flex-direction: column; gap: 0; padding: 0; }
.timeline-compact-item { display: grid; grid-template-columns: 140px 1fr auto; gap: var(--space-3); align-items: start; padding: var(--space-2) var(--space-3); border-left: 2px solid var(--cyan); border-bottom: 1px solid var(--border-subtle); background: transparent; font-family: Consolas, monospace; font-size: 0.75rem; }
.timeline-compact-item:hover { background: var(--surface-elevated); }
.timeline-compact-item.critical { border-left-color: var(--red); background: rgba(239, 68, 68, 0.05); }
.timeline-compact-item.high { border-left-color: var(--orange); }
.timeline-time { color: var(--text-secondary); font-size: 0.7rem; }
.timeline-title { font-weight: 600; color: var(--text-primary); }
.timeline-desc { color: var(--text-secondary); margin-top: 2px; }
.timeline-meta { display: flex; gap: var(--space-2); }
.cluster-count { display: inline-flex; align-items: center; justify-content: center; background: var(--surface-secondary); color: var(--text-secondary); border-radius: 9px; padding: 0 6px; font-size: 0.65rem; border: 1px solid var(--border-subtle); }

/* FASE 6: Rule Studio */
.rule-editor { display: flex; flex-direction: column; gap: var(--space-2); padding: var(--space-3); height: 400px; }
#monacoEditor { flex: 1; border: 1px solid var(--border-subtle); border-radius: 3px; }
#ruleEditor { display: none; } /* Ocultar textarea original, pois usaremos Monaco */
.studio-meta { display: flex; gap: var(--space-2); margin-bottom: var(--space-2); }
.mitre-chip { display: inline-flex; align-items: center; height: 20px; padding: 0 6px; border: 1px solid var(--border-subtle); border-radius: 2px; background: var(--surface-secondary); color: var(--purple); font-family: Consolas, monospace; font-size: 0.65rem; font-weight: 600; }

/* FASE 7: Hunting Chips */
.query-row { display: flex; gap: var(--space-2); padding: var(--space-2) var(--space-3); background: var(--surface-secondary); align-items: center; border-bottom: 1px solid var(--border-subtle); }
.query-chip { display: inline-flex; align-items: center; gap: 4px; height: 22px; padding: 0 8px; border-radius: 11px; background: var(--surface-elevated); border: 1px solid var(--border-strong); color: var(--text-primary); font-size: 0.7rem; cursor: pointer; }
.query-chip:hover { background: var(--border-subtle); }

/* FASE 8: Focus Mode */
.focus-toggle { margin-left: auto; }

/* Outros componentes */
.chart-box { height: 200px; padding: var(--space-2); }
.map-stage { height: 240px; margin: var(--space-2); background: var(--surface-secondary); border: 1px solid var(--border-subtle); border-radius: 3px; overflow: hidden; position: relative; }
.world { opacity: 0.2; width: 100%; height: 100%; }

.rank-list { display: flex; flex-direction: column; padding: var(--space-2); gap: 2px; }
.rank-item { display: flex; justify-content: space-between; align-items: center; padding: 6px var(--space-2); background: transparent; border-bottom: 1px solid var(--border-subtle); font-family: Consolas, monospace; font-size: 0.75rem; border-radius: 0; }
.rank-item:hover { background: var(--surface-elevated); }
.empty-state { padding: var(--space-4); text-align: center; color: var(--text-muted); font-size: 0.75rem; font-family: Consolas, monospace; }

.critical-banner { display: none; padding: var(--space-2); text-align: center; background: rgba(239, 68, 68, 0.1); border: 1px solid var(--red); color: var(--red); font-weight: 600; font-size: 0.8rem; margin-bottom: var(--space-3); border-radius: 3px; }
.critical-banner.show { display: block; }
.incident-panel { margin-bottom: var(--space-3); }
.product-grid { display: grid; grid-template-columns: 1fr 1fr; gap: var(--space-3); margin-bottom: var(--space-3); }
.product-panel { display: flex; flex-direction: column; }

/* Scrollbars */
*::-webkit-scrollbar { width: 6px; height: 6px; }
*::-webkit-scrollbar-track { background: var(--surface-primary); }
*::-webkit-scrollbar-thumb { background: var(--surface-elevated); border-radius: 3px; }
*::-webkit-scrollbar-thumb:hover { background: var(--border-strong); }

@media (max-width: 1200px) {
    .grid { grid-template-columns: 1fr; grid-template-areas: "analytics" "map" "feed"; }
    .product-grid { grid-template-columns: 1fr; }
}
</style>
"""

html_content = html_content[:css_start] + new_css + html_content[css_end:]

# 2. Add Monaco Editor script
head_end = html_content.find("</head>")
monaco_script = '<script src="https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.38.0/min/vs/loader.min.js"></script>\n'
html_content = html_content[:head_end] + monaco_script + html_content[head_end:]

# 3. Modify Rule Studio HTML
rule_studio_start = html_content.find('<section class="panel product-panel" id="ruleStudio">')
rule_studio_end = html_content.find('</section>', rule_studio_start) + 10

new_rule_studio = """<section class="panel product-panel essential-panel" id="ruleStudio">
    <div class="panel-head">
        <div>
            <h2 class="panel-title">Rule Studio Enterprise</h2>
        </div>
        <div class="live" id="ruleStudioStatus">VALIDAÇÃO</div>
    </div>
    <div class="rule-editor">
        <div class="studio-meta">
            <span class="mitre-chip">YAML/JSON Engine</span>
            <span class="mitre-chip" id="rulePreviewSeverity">SEVERIDADE</span>
            <span class="mitre-chip" id="rulePreviewMitre">MITRE</span>
        </div>
        <textarea id="ruleEditor"></textarea>
        <div id="monacoEditor"></div>
        <div class="toolbar">
            <button class="button" id="validateRuleButton" type="button">Validar</button>
            <button class="button" id="simulateRuleButton" type="button">Simular</button>
            <button class="button demo" id="saveRuleButton" type="button">Salvar Regra</button>
        </div>
        <div class="rank-list" id="ruleStudioResults"></div>
    </div>
</section>"""

html_content = html_content[:rule_studio_start] + new_rule_studio + html_content[rule_studio_end:]

# 4. Modify Feed rendering in JS to support Timeline FASE 5 (Clusterization) and Feed Sticky headers
render_feed_start = html_content.find('function renderFeed(alerts) {')
render_feed_end = html_content.find('function applyRealtimeAlert', render_feed_start)

new_render_feed = """function renderFeed(alerts) {
    const tbody = el('feedBody');
    if (!alerts.length) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:40px; color:var(--text-muted)">Aguardando eventos...</td></tr>';
        return;
    }
    
    // FASE 4: Feed Operacional Premium (Agrupamento Temporal)
    let lastTime = '';
    let html = '';
    
    alerts.slice(0, 50).forEach(a => {
        const dateObj = new Date(a.ts || a.timestamp);
        const timeStr = dateObj.toLocaleTimeString('pt-BR', {hour: '2-digit', minute: '2-digit'});
        
        if (timeStr !== lastTime) {
            html += `<tr><td colspan="8" class="time-sep">${timeStr}</td></tr>`;
            lastTime = timeStr;
        }
        
        const sev = severity(a);
        const color = getSeverityColor(sev);
        const [action, actionClass] = socAction(a);
        html += `
            <tr class="clickable-row" data-alert-id="${esc(a.id)}">
                <td class="mono" style="border-left:2px solid ${color}">${esc(dateObj.toLocaleTimeString('pt-BR'))}</td>
                <td class="mono">${esc(a.source_ip || a.ip)} &rarr; ${esc(a.target_host || 'local')}</td>
                <td><span class="tag ${sev}" style="color:${color}; border-color:${color}">${esc(translateSeverity(sev))}</span></td>
                <td class="mono" style="color:${color}">${risk(a)}</td>
                <td><div class="tag low">${a.occurrence_count > 1 ? 'Cluster' : 'Raw'}</div></td>
                <td class="mono">${esc(a.mitre_id || 'N/D')}</td>
                <td class="muted">${esc(a.score_explanation || 'Sem observações')}</td>
                <td><span class="action ${actionClass}">${esc(action)}</span></td>
            </tr>
        `;
    });
    tbody.innerHTML = html;
}

// FASE 5: Timeline Clusterization
async function refreshEnterpriseTimeline(incidentId) {
    if (!incidentId) return;
    const data = await apiRequest(`/api/incidents/${encodeURIComponent(incidentId)}/timeline`);
    if (!data) return;
    
    // Agrupar eventos similares
    const timelineEvents = data.timeline || [];
    const clusters = [];
    
    timelineEvents.forEach(item => {
        const last = clusters[clusters.length - 1];
        if (last && last.event_type === item.event_type && last.mitre_technique === item.mitre_technique) {
            last.count = (last.count || 1) + 1;
            last.accumulated_score = Math.max(last.accumulated_score, item.accumulated_score);
        } else {
            clusters.push({...item, count: 1});
        }
    });

    el('enterpriseTimeline').innerHTML = clusters.slice(0, 15).map(item => {
        const sev = normalizeSeverityLabel(item.severity);
        const countBadge = item.count > 1 ? `<span class="cluster-count">${item.count} eventos agrupados</span>` : '';
        return `
            <div class="timeline-compact-item ${sev}">
                <div class="timeline-time">${esc(new Date(item.timestamp).toLocaleTimeString('pt-BR'))}</div>
                <div>
                    <div class="timeline-title">${esc(item.event_type)} ${countBadge}</div>
                    <div class="timeline-desc">${esc(item.message)}</div>
                </div>
                <div class="timeline-meta">
                    <span class="tag low">${esc(item.mitre_technique || 'MITRE N/D')}</span>
                    <span class="tag high">Score ${esc(item.accumulated_score)}</span>
                </div>
            </div>
        `;
    }).join('') || renderEmptyState('Sem eventos', 'Timeline vazia.');
}

"""

html_content = html_content[:render_feed_start] + new_render_feed + html_content[render_feed_end:]

# 5. Add Focus Mode button to Header
toolbar_start = html_content.find('<div class="toolbar">')
mode_toggle_start = html_content.find('<div class="mode-toggle"', toolbar_start)

focus_btn = '<button class="button focus-toggle" id="focusModeButton" type="button">SOC Focus</button>\n'
html_content = html_content[:mode_toggle_start] + focus_btn + html_content[mode_toggle_start:]

# 6. Initialize Monaco Editor in JS
init_js_start = html_content.rfind('// Inicialização')
monaco_init = """
        // FASE 6: Monaco Editor Initialization
        let editorInstance;
        require.config({ paths: { 'vs': 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.38.0/min/vs' }});
        require(['vs/editor/editor.main'], function() {
            editorInstance = monaco.editor.create(document.getElementById('monacoEditor'), {
                value: JSON.stringify(defaultRule(), null, 2),
                language: 'json',
                theme: 'vs-dark',
                minimap: { enabled: false },
                lineNumbers: 'on',
                scrollBeyondLastLine: false,
                fontSize: 12,
                fontFamily: '"JetBrains Mono", Consolas, monospace',
                renderLineHighlight: 'all',
                automaticLayout: true
            });
            
            editorInstance.onDidChangeModelContent(() => {
                document.getElementById('ruleEditor').value = editorInstance.getValue();
                updateRulePreview();
            });
            document.getElementById('ruleEditor').value = editorInstance.getValue();
        });

        // FASE 8: Focus Mode Toggle
        document.getElementById('focusModeButton').addEventListener('click', () => {
            document.body.classList.toggle('focus-mode');
            const btn = document.getElementById('focusModeButton');
            btn.textContent = document.body.classList.contains('focus-mode') ? 'Exit Focus' : 'SOC Focus';
        });
        
        // Add essential class to necessary panels
        ['incidentsListPanel', 'productConsole', 'huntingConsole', 'ruleStudio'].forEach(id => {
            const el = document.getElementById(id);
            if(el) el.classList.add('essential-panel');
        });
"""

html_content = html_content[:init_js_start] + monaco_init + html_content[init_js_start:]

# Escrever arquivo alterado
with open(file_path, "w", encoding="utf-8") as f:
    f.write(html_content)

print("Refactor concluído com sucesso!")
